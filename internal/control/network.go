package control

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"time"
)

const defaultNetworkSocket = "/run/cherrywaf/netd.sock"

type NetworkPlan struct {
	Version     int      `json:"version"`
	Interface   string   `json:"interface"`
	DHCP4       bool     `json:"dhcp4"`
	Addresses   []string `json:"addresses,omitempty"`
	Gateway4    string   `json:"gateway4,omitempty"`
	Nameservers []string `json:"nameservers,omitempty"`
	MTU         int      `json:"mtu,omitempty"`
}

type NetworkInterface struct {
	Name         string   `json:"name"`
	HardwareAddr string   `json:"hardware_address,omitempty"`
	Flags        []string `json:"flags"`
	Addresses    []string `json:"addresses"`
	MTU          int      `json:"mtu"`
}

type NetworkApplyResult struct {
	Token       string    `json:"token"`
	ConfirmBy   time.Time `json:"confirm_by"`
	Message     string    `json:"message"`
	RollbackSec int       `json:"rollback_seconds"`
}

func (c *Controller) networkSocket() string {
	if value := strings.TrimSpace(c.opts.NetworkSocket); value != "" {
		return value
	}
	return defaultNetworkSocket
}

func (c *Controller) handleNetworkStatus(w http.ResponseWriter, _ *http.Request, _ Principal) {
	interfaces, err := LocalNetworkInterfaces()
	if err != nil {
		writeAPIError(w, http.StatusInternalServerError, err.Error())
		return
	}
	response := map[string]any{"interfaces": interfaces, "helper_available": false, "socket": c.networkSocket()}
	var helper any
	if err := c.networkRequest(http.MethodGet, "/v1/status", nil, &helper); err == nil {
		response["helper_available"] = true
		response["helper"] = helper
	} else {
		response["helper_error"] = err.Error()
	}
	writeJSON(w, http.StatusOK, response)
}

func (c *Controller) handleNetworkValidate(w http.ResponseWriter, r *http.Request, principal Principal) {
	var plan NetworkPlan
	if err := decodeJSON(r, &plan, 256<<10); err != nil {
		writeAPIError(w, http.StatusBadRequest, err.Error())
		return
	}
	known, err := localInterfaceSet()
	if err != nil {
		writeAPIError(w, http.StatusInternalServerError, err.Error())
		return
	}
	if err := ValidateNetworkPlan(plan, known); err != nil {
		c.audit(r, principal, "network.validate", "network/"+plan.Interface, "failure", map[string]any{"error": err.Error()})
		writeAPIError(w, http.StatusBadRequest, err.Error())
		return
	}
	yaml, err := RenderNetplan(plan)
	if err != nil {
		writeAPIError(w, http.StatusBadRequest, err.Error())
		return
	}
	c.audit(r, principal, "network.validate", "network/"+plan.Interface, "success", nil)
	writeJSON(w, http.StatusOK, map[string]any{"valid": true, "netplan": yaml})
}

func (c *Controller) handleNetworkApply(w http.ResponseWriter, r *http.Request, principal Principal) {
	var plan NetworkPlan
	if err := decodeJSON(r, &plan, 256<<10); err != nil {
		writeAPIError(w, http.StatusBadRequest, err.Error())
		return
	}
	known, err := localInterfaceSet()
	if err != nil {
		writeAPIError(w, http.StatusInternalServerError, err.Error())
		return
	}
	if err := ValidateNetworkPlan(plan, known); err != nil {
		writeAPIError(w, http.StatusBadRequest, err.Error())
		return
	}
	var result NetworkApplyResult
	if err := c.networkRequest(http.MethodPost, "/v1/apply", plan, &result); err != nil {
		c.audit(r, principal, "network.apply", "network/"+plan.Interface, "failure", map[string]any{"error": err.Error()})
		writeAPIError(w, http.StatusServiceUnavailable, "privileged network helper failed: "+err.Error())
		return
	}
	c.audit(r, principal, "network.apply", "network/"+plan.Interface, "success", map[string]any{"token": result.Token, "confirm_by": result.ConfirmBy})
	writeJSON(w, http.StatusAccepted, result)
}

func (c *Controller) handleNetworkConfirm(w http.ResponseWriter, r *http.Request, principal Principal) {
	c.handleNetworkTokenAction(w, r, principal, "/v1/confirm", "network.confirm")
}

func (c *Controller) handleNetworkRollback(w http.ResponseWriter, r *http.Request, principal Principal) {
	c.handleNetworkTokenAction(w, r, principal, "/v1/rollback", "network.rollback")
}

func (c *Controller) handleNetworkTokenAction(w http.ResponseWriter, r *http.Request, principal Principal, path, action string) {
	var input struct {
		Token string `json:"token"`
	}
	if err := decodeJSON(r, &input, 64<<10); err != nil {
		writeAPIError(w, http.StatusBadRequest, err.Error())
		return
	}
	if !validNetworkToken(input.Token) {
		writeAPIError(w, http.StatusBadRequest, "invalid network change token")
		return
	}
	var response any
	if err := c.networkRequest(http.MethodPost, path, input, &response); err != nil {
		c.audit(r, principal, action, "network/change", "failure", map[string]any{"error": err.Error()})
		writeAPIError(w, http.StatusServiceUnavailable, err.Error())
		return
	}
	c.audit(r, principal, action, "network/change", "success", map[string]any{"token": input.Token})
	writeJSON(w, http.StatusOK, response)
}

func (c *Controller) networkRequest(method, path string, input, output any) error {
	var body io.Reader
	if input != nil {
		data, err := json.Marshal(input)
		if err != nil {
			return err
		}
		body = bytes.NewReader(data)
	}
	request, err := http.NewRequest(method, "http://unix"+path, body)
	if err != nil {
		return err
	}
	request.Header.Set("Content-Type", "application/json")
	transport := &http.Transport{DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
		var dialer net.Dialer
		return dialer.DialContext(ctx, "unix", c.networkSocket())
	}, DisableKeepAlives: true}
	client := &http.Client{Transport: transport, Timeout: 90 * time.Second}
	response, err := client.Do(request)
	if err != nil {
		return err
	}
	defer response.Body.Close()
	data, err := io.ReadAll(io.LimitReader(response.Body, 1<<20))
	if err != nil {
		return err
	}
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		var apiErr struct {
			Error string `json:"error"`
		}
		if json.Unmarshal(data, &apiErr) == nil && apiErr.Error != "" {
			return errors.New(apiErr.Error)
		}
		return fmt.Errorf("network helper returned HTTP %d", response.StatusCode)
	}
	if output != nil && len(data) > 0 {
		return json.Unmarshal(data, output)
	}
	return nil
}

func LocalNetworkInterfaces() ([]NetworkInterface, error) {
	interfaces, err := net.Interfaces()
	if err != nil {
		return nil, err
	}
	result := make([]NetworkInterface, 0, len(interfaces))
	for _, item := range interfaces {
		addresses, _ := item.Addrs()
		addressStrings := make([]string, 0, len(addresses))
		for _, address := range addresses {
			addressStrings = append(addressStrings, address.String())
		}
		flags := strings.Fields(strings.ReplaceAll(item.Flags.String(), "|", " "))
		result = append(result, NetworkInterface{Name: item.Name, HardwareAddr: item.HardwareAddr.String(), Flags: flags, Addresses: addressStrings, MTU: item.MTU})
	}
	sort.Slice(result, func(i, j int) bool { return result[i].Name < result[j].Name })
	return result, nil
}

func localInterfaceSet() (map[string]bool, error) {
	interfaces, err := net.Interfaces()
	if err != nil {
		return nil, err
	}
	result := make(map[string]bool, len(interfaces))
	for _, item := range interfaces {
		result[item.Name] = true
	}
	return result, nil
}

func ValidateNetworkPlan(plan NetworkPlan, known map[string]bool) error {
	if plan.Version == 0 {
		plan.Version = 1
	}
	if plan.Version != 1 {
		return errors.New("unsupported network plan version")
	}
	if !validInterfaceName(plan.Interface) {
		return errors.New("invalid network interface name")
	}
	if plan.Interface == "lo" {
		return errors.New("loopback interface cannot be configured")
	}
	if known != nil && !known[plan.Interface] {
		return fmt.Errorf("network interface %q does not exist", plan.Interface)
	}
	if plan.MTU != 0 && (plan.MTU < 576 || plan.MTU > 9216) {
		return errors.New("MTU must be between 576 and 9216")
	}
	if plan.DHCP4 {
		if len(plan.Addresses) > 0 || plan.Gateway4 != "" {
			return errors.New("DHCP mode cannot define static addresses or gateway")
		}
	} else {
		if len(plan.Addresses) == 0 {
			return errors.New("at least one static address is required when DHCP is disabled")
		}
		for _, value := range plan.Addresses {
			ip, _, err := net.ParseCIDR(value)
			if err != nil || ip == nil {
				return fmt.Errorf("invalid CIDR address %q", value)
			}
		}
		if plan.Gateway4 != "" {
			ip := net.ParseIP(plan.Gateway4)
			if ip == nil || ip.To4() == nil {
				return errors.New("gateway4 must be a valid IPv4 address")
			}
		}
	}
	if len(plan.Nameservers) > 6 {
		return errors.New("a maximum of six DNS servers is supported")
	}
	for _, value := range plan.Nameservers {
		if net.ParseIP(value) == nil {
			return fmt.Errorf("invalid DNS server %q", value)
		}
	}
	return nil
}

func RenderNetplan(plan NetworkPlan) (string, error) {
	if err := ValidateNetworkPlan(plan, nil); err != nil {
		return "", err
	}
	var b strings.Builder
	b.WriteString("network:\n  version: 2\n  renderer: networkd\n  ethernets:\n    ")
	b.WriteString(plan.Interface)
	b.WriteString(":\n")
	b.WriteString("      dhcp4: ")
	b.WriteString(strconv.FormatBool(plan.DHCP4))
	b.WriteString("\n      dhcp6: false\n")
	if plan.MTU != 0 {
		b.WriteString("      mtu: ")
		b.WriteString(strconv.Itoa(plan.MTU))
		b.WriteByte('\n')
	}
	if !plan.DHCP4 {
		b.WriteString("      addresses:\n")
		for _, address := range plan.Addresses {
			b.WriteString("        - ")
			b.WriteString(address)
			b.WriteByte('\n')
		}
		if plan.Gateway4 != "" {
			b.WriteString("      routes:\n        - to: default\n          via: ")
			b.WriteString(plan.Gateway4)
			b.WriteByte('\n')
		}
	}
	if len(plan.Nameservers) > 0 {
		b.WriteString("      nameservers:\n        addresses:\n")
		for _, address := range plan.Nameservers {
			b.WriteString("          - ")
			b.WriteString(address)
			b.WriteByte('\n')
		}
	}
	return b.String(), nil
}

func validInterfaceName(value string) bool {
	if value == "" || len(value) > 15 || strings.Contains(value, "..") {
		return false
	}
	for _, r := range value {
		if (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') || r == '-' || r == '_' || r == '.' {
			continue
		}
		return false
	}
	return true
}

func validNetworkToken(value string) bool {
	if len(value) != 32 {
		return false
	}
	for _, r := range value {
		if (r >= 'a' && r <= 'f') || (r >= '0' && r <= '9') {
			continue
		}
		return false
	}
	return true
}
