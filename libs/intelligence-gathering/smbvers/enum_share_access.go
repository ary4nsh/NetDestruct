package smbvers

import (
	"strings"
)

// TestShareAccess checks whether a share can be mounted and listed using native SMB2.
func TestShareAccess(host string, port int, user, pass, domain, share, shareType string) ShareAccess {
	if port <= 0 {
		port = portDirect
	}
	if strings.EqualFold(shareType, "IPC") || strings.EqualFold(share, "IPC$") {
		return ShareAccess{Mapping: "ok", Listing: "not supported"}
	}
	s, out, err := OpenSMBSession(host, port, user, pass, domain)
	if err != nil {
		return classifyShareMountError(err)
	}
	defer s.Close()
	if out != LoginSuccess && out != LoginGuest {
		return ShareAccess{Mapping: "denied", Listing: "n/a"}
	}
	path := utf16LEPath(host, share)
	treeID, err := s.treeConnect(path)
	if err != nil {
		return classifyShareMountError(err)
	}
	defer s.treeDisconnect(treeID)
	fid, err := s.openDirectory(treeID, "")
	if err != nil {
		return classifyShareMountError(err)
	}
	defer s.closeFileOnTree(treeID, fid)
	if err := s.queryDirectory(treeID, fid); err != nil {
		return classifyShareListError(err)
	}
	return ShareAccess{Mapping: "ok", Listing: "ok"}
}

func classifyShareMountError(err error) ShareAccess {
	switch shareErrKind(err) {
	case "access_denied":
		return ShareAccess{Mapping: "denied", Listing: "n/a"}
	default:
		return ShareAccess{Mapping: "denied", Listing: "n/a"}
	}
}

func classifyShareListError(err error) ShareAccess {
	switch shareErrKind(err) {
	case "access_denied":
		return ShareAccess{Mapping: "ok", Listing: "denied"}
	case "wrong_password":
		return ShareAccess{Mapping: "ok", Listing: "wrong password"}
	case "not_supported":
		return ShareAccess{Mapping: "ok", Listing: "not supported"}
	default:
		return ShareAccess{Mapping: "ok", Listing: "not supported"}
	}
}

func shareErrKind(err error) string {
	if err == nil {
		return ""
	}
	if st, ok := smbStatusFromErr(err); ok {
		switch st {
		case stAccessDenied:
			return "access_denied"
		case stWrongPassword:
			return "wrong_password"
		case stInvalidInfoClass, stConnectionRefused, stNetworkAccessDenied, stNotADirectory, stNoSuchFile, stInvalidParameter:
			return "not_supported"
		}
	}
	msg := strings.ToUpper(err.Error())
	switch {
	case strings.Contains(msg, "STATUS_ACCESS_DENIED"), strings.Contains(msg, "0XC0000022"):
		return "access_denied"
	case strings.Contains(msg, "STATUS_WRONG_PASSWORD"), strings.Contains(msg, "0XC000006A"):
		return "wrong_password"
	case strings.Contains(msg, "STATUS_INVALID_INFO_CLASS"),
		strings.Contains(msg, "STATUS_CONNECTION_REFUSED"),
		strings.Contains(msg, "STATUS_NETWORK_ACCESS_DENIED"),
		strings.Contains(msg, "STATUS_NOT_A_DIRECTORY"),
		strings.Contains(msg, "STATUS_NO_SUCH_FILE"),
		strings.Contains(msg, "STATUS_INVALID_PARAMETER"):
		return "not_supported"
	case strings.Contains(msg, "TREE CONNECT"):
		if strings.Contains(msg, "ACCESS_DENIED") || strings.Contains(msg, "0XC0000022") {
			return "access_denied"
		}
	}
	return "unknown"
}
