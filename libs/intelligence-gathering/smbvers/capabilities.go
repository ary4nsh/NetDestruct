package smbvers

type smb2CapBit struct {
	mask uint32
	name string
}

// Order matches NEGPROT_CAP_* / hf_smb2_cap_* (LSB first).
var smb2CapBits = []smb2CapBit{
	{capDFS, "DFS"},
	{capLeasing, "LEASING"},
	{capLargeMTU, "LARGE MTU"},
	{capMultiChannel, "MULTI CHANNEL"},
	{capPersistent, "PERSISTENT HANDLES"},
	{capDirectoryLease, "DIRECTORY LEASING"},
	{capEncryption, "ENCRYPTION"},
	{capNotifications, "NOTIFICATIONS"},
}

const capNotifications = 0x00000080

// capabilityMaskForDialect limits which bits are meaningful for the negotiated revision ([MS-SMB2]).
func capabilityMaskForDialect(dialect uint16) uint32 {
	switch dialect {
	case 0x0202:
		return capDFS
	case 0x0210:
		return capDFS | capLeasing | capLargeMTU
	case 0x0300, 0x0302:
		return capDFS | capLeasing | capLargeMTU | capMultiChannel | capPersistent | capDirectoryLease | capEncryption
	case 0x0311:
		return capDFS | capLeasing | capLargeMTU | capMultiChannel | capPersistent | capDirectoryLease | capEncryption | capNotifications
	default:
		return 0xffffffff
	}
}

func maskServerCapabilities(dialect uint16, raw uint32) uint32 {
	return raw & capabilityMaskForDialect(dialect)
}

func supportedCapabilityNames(cap uint32) []string {
	var names []string
	for _, b := range smb2CapBits {
		if cap&b.mask != 0 {
			names = append(names, b.name)
		}
	}
	return names
}
