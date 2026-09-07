package smbvers

import (
	"fmt"
	"io"
	"math"
	"strings"
	"time"
)

var domainPasswordFlags = []struct {
	mask uint32
	name string
}{
	{0x00000001, "DOMAIN_PASSWORD_COMPLEX"},
	{0x00000002, "DOMAIN_PASSWORD_NO_ANON_CHANGE"},
	{0x00000004, "DOMAIN_PASSWORD_NO_CLEAR_CHANGE"},
	{0x00000008, "DOMAIN_PASSWORD_LOCKOUT_ADMINS"},
	{0x00000010, "DOMAIN_PASSWORD_PASSWORD_STORE_CLEARTEXT"},
	{0x00000020, "DOMAIN_PASSWORD_REFUSE_PASSWORD_CHANGE"},
}

func printEnumBanner(w io.Writer, title, host string) {
	line := strings.Repeat("=", 41)
	fmt.Fprintf(w, "\n %s\n", line)
	fmt.Fprintf(w, "| %s |\n", centerEnumTitle(title, host, 39))
	fmt.Fprintf(w, " %s\n", line)
}

func centerEnumTitle(title, host string, width int) string {
	text := fmt.Sprintf("%s %s", title, host)
	if len(text) >= width {
		return text
	}
	pad := width - len(text)
	left := pad / 2
	right := pad - left
	return strings.Repeat(" ", left) + text + strings.Repeat(" ", right)
}

func printEnumInfo(w io.Writer, msg string) {
	fmt.Fprintf(w, "\x1b[33m[*]\x1b[0m %s\n", msg)
}

func printEnumSuccess(w io.Writer, msg string) {
	fmt.Fprintf(w, "\x1b[32m[+]\x1b[0m %s\n", msg)
}

func formatPolicyCount(v uint16) string {
	if v == 0 {
		return "None"
	}
	return fmt.Sprintf("%d", v)
}

func formatSamrAge(age samrAge, lockout bool) string {
	low := age.LowPart
	high := age.HighPart

	if !lockout {
		if low == 0 && high == int32(-2147483648) {
			return "not set"
		}
		if low == 0 && high == 0 {
			return "none"
		}
		var tmp float64
		if low != 0 {
			tmp = float64(uint64(low)+uint64(abs32(high+1))*0x100000000) * 1e-7
		} else {
			tmp = float64(uint64(abs32(high))*0x100000000+uint64(abs32(int32(low)))) * 1e-7
		}
		return formatPolicyDuration(tmp)
	}

	tmp := math.Abs(float64(high)) * 1e-7
	if tmp == 0 {
		return "none"
	}
	return formatPolicyDuration(tmp)
}

func formatLockoutInterval(v int64) string {
	if v == 0 {
		return "none"
	}
	sec := math.Abs(float64(v)) * 1e-7
	return formatPolicyDuration(sec)
}

func formatPolicyDuration(seconds float64) string {
	if seconds <= 0 {
		return "none"
	}
	dt := time.Unix(int64(seconds), 0).UTC()
	diff := dt.Sub(time.Unix(0, 0).UTC())
	days := diff / (24 * time.Hour)
	years := dt.Year() - 1970

	var parts []string
	if days > 1 {
		parts = append(parts, fmt.Sprintf("%d days", days))
	} else if days == 1 {
		parts = append(parts, "1 day")
	}
	if years == 1 {
		parts = append(parts, "(1 year)")
	} else if years > 1 {
		parts = append(parts, fmt.Sprintf("(%d years)", years))
	}
	if dt.Hour() > 1 {
		parts = append(parts, fmt.Sprintf("%d hours", dt.Hour()))
	} else if dt.Hour() == 1 {
		parts = append(parts, "1 hour")
	}
	if dt.Minute() > 1 {
		parts = append(parts, fmt.Sprintf("%d minutes", dt.Minute()))
	} else if dt.Minute() == 1 {
		parts = append(parts, "1 minute")
	}
	if len(parts) == 0 {
		return "none"
	}
	return strings.TrimSpace(strings.Join(parts, " "))
}

func abs32(v int32) int32 {
	if v < 0 {
		return -v
	}
	return v
}

func printPasswordPolicy(w io.Writer, pol *PasswordPolicy) {
	if pol == nil {
		return
	}
	fmt.Fprintf(w, "Domain password information:\n")
	printKV(w, "Password history length", formatPolicyCount(pol.HistoryLength))
	printKV(w, "Minimum password length", formatPolicyCount(pol.MinLength))
	printKV(w, "Minimum password age", formatSamrAge(pol.MinPasswordAge, false))
	printKV(w, "Maximum password age", formatSamrAge(pol.MaxPasswordAge, false))
	fmt.Fprintf(w, "  Password properties:\n")
	for _, f := range domainPasswordFlags {
		val := pol.PasswordProperties&f.mask == f.mask
		fmt.Fprintf(w, "  - %s: %t\n", f.name, val)
	}
	fmt.Fprintf(w, "Domain lockout information:\n")
	printKV(w, "Lockout observation window", formatLockoutInterval(pol.LockoutWindow))
	printKV(w, "Lockout duration", formatLockoutInterval(pol.LockoutDuration))
	printKV(w, "Lockout threshold", formatPolicyCount(pol.LockoutThreshold))
	fmt.Fprintf(w, "Domain logoff information:\n")
	printKV(w, "Force logoff time", formatSamrAge(pol.ForceLogoff, false))
}

func formatShareAccessResult(a ShareAccess) string {
	mapLabel := strings.ToUpper(a.Mapping)
	listLabel := strings.ToUpper(a.Listing)
	switch a.Listing {
	case "ok":
		listLabel = "OK"
	case "denied":
		listLabel = "DENIED"
	case "not supported":
		listLabel = "NOT SUPPORTED"
	case "wrong password":
		listLabel = "WRONG PASSWORD"
	case "n/a":
		listLabel = "N/A"
	}
	if mapLabel == "ok" {
		mapLabel = "OK"
	} else if mapLabel == "denied" {
		mapLabel = "DENIED"
	}
	return fmt.Sprintf("Mapping: %s, Listing: %s", mapLabel, listLabel)
}
