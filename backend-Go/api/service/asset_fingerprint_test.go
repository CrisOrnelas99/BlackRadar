// Package service verifies asset fingerprint normalization behavior.
package service

import (
	"testing"

	"secureops/backend-go/api/model"
)

func TestBuildAssetFingerprintUsesExplicitHints(t *testing.T) {
	asset := model.Asset{
		Name:            "Dell Latitude 7420",
		Type:            "Laptop",
		OperatingSystem: ptrString("Windows 11 Pro"),
	}
	fingerprint := BuildAssetFingerprint(asset, "Vendor: Dell\nProduct: Latitude 7420\nVersion: 1.2\nOperating System: Windows 11 Pro\nModel: 7420")

	if fingerprint.Vendor != "dell" {
		t.Fatalf("expected vendor dell, got %q", fingerprint.Vendor)
	}
	if fingerprint.Product != "latitude 7420" {
		t.Fatalf("expected product latitude 7420, got %q", fingerprint.Product)
	}
	if fingerprint.Version != "1.2" {
		t.Fatalf("expected version 1.2, got %q", fingerprint.Version)
	}
	if fingerprint.OperatingSystem != "windows 11 pro" {
		t.Fatalf("expected os windows 11 pro, got %q", fingerprint.OperatingSystem)
	}
	if fingerprint.DeviceModel != "7420" {
		t.Fatalf("expected model 7420, got %q", fingerprint.DeviceModel)
	}
	if fingerprint.Canonical != "vendor=dell;product=latitude 7420;version=1.2;operating_system=windows 11 pro;device_model=7420;asset_name=dell latitude 7420;asset_type=laptop" {
		t.Fatalf("unexpected canonical fingerprint: %q", fingerprint.Canonical)
	}
}

func TestBuildAssetFingerprintParsesSentenceStyleHints(t *testing.T) {
	asset := model.Asset{
		Name:            "Chrome Desktop",
		Type:            "Desktop",
		OperatingSystem: ptrString("Windows 11"),
	}
	fingerprint := BuildAssetFingerprint(asset, "The vendor is Google, the product is Chrome, version 138.0.7204.156, operating system Windows 11, model Desktop.")

	if fingerprint.Vendor != "google" {
		t.Fatalf("expected vendor google, got %q", fingerprint.Vendor)
	}
	if fingerprint.Product != "chrome" {
		t.Fatalf("expected product chrome, got %q", fingerprint.Product)
	}
	if fingerprint.Version != "138.0.7204.156" {
		t.Fatalf("expected version 138.0.7204.156, got %q", fingerprint.Version)
	}
	if fingerprint.OperatingSystem != "windows 11" {
		t.Fatalf("expected os windows 11, got %q", fingerprint.OperatingSystem)
	}
	if fingerprint.DeviceModel != "desktop" {
		t.Fatalf("expected model desktop, got %q", fingerprint.DeviceModel)
	}
}

func TestBuildAssetFingerprintParsesPackageFromProjectSentence(t *testing.T) {
	asset := model.Asset{
		Name:            "Linux Server",
		Type:            "Server",
		OperatingSystem: ptrString("Linux"),
	}
	fingerprint := BuildAssetFingerprint(asset, "This Linux server is running a compression utility. It has the xz package installed from the Tukaani project, specifically release 5.6.1, and liblzma from that package is present on the host.")

	if fingerprint.Vendor != "tukaani" {
		t.Fatalf("expected vendor tukaani, got %q", fingerprint.Vendor)
	}
	if fingerprint.Product != "xz" {
		t.Fatalf("expected product xz, got %q", fingerprint.Product)
	}
	if fingerprint.Version != "5.6.1" {
		t.Fatalf("expected version 5.6.1, got %q", fingerprint.Version)
	}
	if fingerprint.OperatingSystem != "linux" {
		t.Fatalf("expected os linux, got %q", fingerprint.OperatingSystem)
	}
}

func TestBuildAssetFingerprintParsesApacheHTTPServerSentence(t *testing.T) {
	asset := model.Asset{
		Name:            "Web Host",
		Type:            "Server",
		OperatingSystem: ptrString("Linux"),
	}
	fingerprint := BuildAssetFingerprint(asset, "A Linux web host in inventory is running Apache HTTP Server release 2.4.49. It is exposed as the web service on this server.")

	if fingerprint.Vendor != "apache" {
		t.Fatalf("expected vendor apache, got %q", fingerprint.Vendor)
	}
	if fingerprint.Product != "http server" {
		t.Fatalf("expected product http server, got %q", fingerprint.Product)
	}
	if fingerprint.Version != "2.4.49" {
		t.Fatalf("expected version 2.4.49, got %q", fingerprint.Version)
	}
}

func TestBuildAssetFingerprintFallsBackToAssetFields(t *testing.T) {
	asset := model.Asset{
		Name:            "HPE ProLiant DL380 Gen10",
		Type:            "Server",
		OperatingSystem: ptrString("Red Hat Enterprise Linux 9"),
	}
	fingerprint := BuildAssetFingerprint(asset, "")

	if fingerprint.Vendor != "" {
		t.Fatalf("expected vendor to stay empty without an explicit hint, got %q", fingerprint.Vendor)
	}
	if fingerprint.Product != "" {
		t.Fatalf("expected product to stay empty without an explicit hint, got %q", fingerprint.Product)
	}
	if fingerprint.OperatingSystem != "red hat enterprise linux 9" {
		t.Fatalf("expected os fallback from asset operating system, got %q", fingerprint.OperatingSystem)
	}
	if fingerprint.DeviceModel != "gen10" {
		t.Fatalf("expected model hint from asset name, got %q", fingerprint.DeviceModel)
	}
	if fingerprint.AssetType != "server" {
		t.Fatalf("expected asset type server, got %q", fingerprint.AssetType)
	}
}

func ptrString(value string) *string {
	return &value
}
