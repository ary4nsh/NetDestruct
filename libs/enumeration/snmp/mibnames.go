package snmp

import (
	"strconv"
	"strings"
)

type mibEntry struct {
	oid  []int
	name string
}

var (
	mibNames []mibEntry
	mibTrie  map[int]*mibNode
)

type mibNode struct {
	name     string
	children map[int]*mibNode
}

func buildMibTrie() {
	mibTrie = map[int]*mibNode{0: {children: map[int]*mibNode{}}}
	for _, e := range mibNames {
		insertMibName(e.oid, e.name)
	}
}

func insertMibName(oid []int, name string) {
	if len(oid) == 0 {
		return
	}
	node := mibTrie[0]
	for _, c := range oid {
		if node.children == nil {
			node.children = map[int]*mibNode{}
		}
		child, ok := node.children[c]
		if !ok {
			child = &mibNode{children: map[int]*mibNode{}}
			node.children[c] = child
		}
		node = child
	}
	node.name = name
}

// formatSymbolicOID returns a human-readable MIB name such as system.sysDescr.0.
// Prefix nodes (iso/org/dod/internet/mgmt/mib-2 or …/enterprises) are omitted;
// unresolved trailing index components are appended numerically.
func formatSymbolicOID(oid []int) string {
	if len(oid) == 0 {
		return "."
	}
	if mibTrie == nil || len(mibTrie) == 0 {
		return formatOID(oid)
	}

	node := mibTrie[0]
	var parts []string
	i := 0
	for i < len(oid) {
		child, ok := node.children[oid[i]]
		if !ok {
			break
		}
		node = child
		i++
		if node.name != "" {
			parts = append(parts, node.name)
		}
	}
	if len(parts) == 0 {
		return formatOID(oid)
	}
	parts = trimOIDNamePrefix(parts)
	for ; i < len(oid); i++ {
		parts = append(parts, strconv.Itoa(oid[i]))
	}
	return strings.Join(parts, ".")
}

func trimOIDNamePrefix(parts []string) []string {
	for _, anchor := range []string{"mib-2", "enterprises", "internet"} {
		for i, p := range parts {
			if p == anchor {
				return parts[i+1:]
			}
		}
	}
	return parts
}

// FormatSymbolicOID returns a MIB-style OID label for display.
func FormatSymbolicOID(oid []int) string { return formatSymbolicOID(oid) }
