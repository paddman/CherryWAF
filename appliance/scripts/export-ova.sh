#!/usr/bin/env bash
set -euo pipefail

if [[ $# -lt 1 || $# -gt 2 ]]; then
  echo "usage: $0 appliance.qcow2 [output.ova]" >&2
  exit 2
fi
command -v qemu-img >/dev/null || { echo "qemu-img is required" >&2; exit 1; }

qcow2="$(realpath "$1")"
base="$(basename "${qcow2%.qcow2}")"
out="${2:-${base}.ova}"
work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT

vmdk="${base}.vmdk"
ovf="${base}.ovf"
mf="${base}.mf"

qemu-img convert -p -f qcow2 -O vmdk -o subformat=streamOptimized "$qcow2" "$work/$vmdk"
capacity_bytes="$(qemu-img info --output=json "$qcow2" | python3 -c 'import json,sys; print(json.load(sys.stdin)["virtual-size"])')"
capacity_gib="$(( (capacity_bytes + 1073741823) / 1073741824 ))"
file_size="$(stat -c %s "$work/$vmdk")"

cat >"$work/$ovf" <<OVF
<?xml version="1.0" encoding="UTF-8"?>
<Envelope vmw:buildId="build-0" xmlns="http://schemas.dmtf.org/ovf/envelope/1" xmlns:cim="http://schemas.dmtf.org/wbem/wscim/1/common" xmlns:ovf="http://schemas.dmtf.org/ovf/envelope/1" xmlns:rasd="http://schemas.dmtf.org/wbem/wscim/1/cim-schema/2/CIM_ResourceAllocationSettingData" xmlns:vmw="http://www.vmware.com/schema/ovf" xmlns:vssd="http://schemas.dmtf.org/wbem/wscim/1/cim-schema/2/CIM_VirtualSystemSettingData">
  <References>
    <File ovf:href="$vmdk" ovf:id="file1" ovf:size="$file_size"/>
  </References>
  <DiskSection>
    <Info>Virtual disk information</Info>
    <Disk ovf:capacity="$capacity_gib" ovf:capacityAllocationUnits="byte * 2^30" ovf:diskId="vmdisk1" ovf:fileRef="file1" ovf:format="http://www.vmware.com/interfaces/specifications/vmdk.html#streamOptimized"/>
  </DiskSection>
  <NetworkSection>
    <Info>Logical networks</Info>
    <Network ovf:name="VM Network"><Description>CherryWAF appliance network</Description></Network>
  </NetworkSection>
  <VirtualSystem ovf:id="CherryWAF">
    <Info>CherryWAF appliance</Info>
    <Name>CherryWAF</Name>
    <OperatingSystemSection ovf:id="101" vmw:osType="ubuntu64Guest"><Info>Ubuntu Server 24.04 LTS</Info></OperatingSystemSection>
    <VirtualHardwareSection>
      <Info>Virtual hardware requirements</Info>
      <System><vssd:ElementName>Virtual Hardware Family</vssd:ElementName><vssd:InstanceID>0</vssd:InstanceID><vssd:VirtualSystemIdentifier>CherryWAF</vssd:VirtualSystemIdentifier><vssd:VirtualSystemType>vmx-17</vssd:VirtualSystemType></System>
      <Item><rasd:AllocationUnits>hertz * 10^6</rasd:AllocationUnits><rasd:Description>Number of Virtual CPUs</rasd:Description><rasd:ElementName>2 virtual CPU(s)</rasd:ElementName><rasd:InstanceID>1</rasd:InstanceID><rasd:ResourceType>3</rasd:ResourceType><rasd:VirtualQuantity>2</rasd:VirtualQuantity></Item>
      <Item><rasd:AllocationUnits>byte * 2^20</rasd:AllocationUnits><rasd:Description>Memory Size</rasd:Description><rasd:ElementName>2048MB of memory</rasd:ElementName><rasd:InstanceID>2</rasd:InstanceID><rasd:ResourceType>4</rasd:ResourceType><rasd:VirtualQuantity>2048</rasd:VirtualQuantity></Item>
      <Item><rasd:Address>0</rasd:Address><rasd:Description>SCSI Controller</rasd:Description><rasd:ElementName>scsiController0</rasd:ElementName><rasd:InstanceID>3</rasd:InstanceID><rasd:ResourceSubType>VirtualSCSI</rasd:ResourceSubType><rasd:ResourceType>6</rasd:ResourceType></Item>
      <Item><rasd:AddressOnParent>0</rasd:AddressOnParent><rasd:ElementName>Hard Disk 1</rasd:ElementName><rasd:HostResource>ovf:/disk/vmdisk1</rasd:HostResource><rasd:InstanceID>4</rasd:InstanceID><rasd:Parent>3</rasd:Parent><rasd:ResourceType>17</rasd:ResourceType></Item>
      <Item><rasd:AddressOnParent>7</rasd:AddressOnParent><rasd:AutomaticAllocation>true</rasd:AutomaticAllocation><rasd:Connection>VM Network</rasd:Connection><rasd:Description>Ethernet adapter</rasd:Description><rasd:ElementName>Network adapter 1</rasd:ElementName><rasd:InstanceID>5</rasd:InstanceID><rasd:ResourceSubType>VmxNet3</rasd:ResourceSubType><rasd:ResourceType>10</rasd:ResourceType></Item>
    </VirtualHardwareSection>
  </VirtualSystem>
</Envelope>
OVF

(
  cd "$work"
  sha256sum "$ovf" "$vmdk" > "$mf"
  tar --format=ustar -cf "$(realpath -m "$OLDPWD/$out")" "$ovf" "$mf" "$vmdk"
)
echo "Created $out"
