// Package controller tests asset controller request handling.
package controller

import (
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"

	appcontext "secureops/backend-go/api/context"
	"secureops/backend-go/api/dto"
	"secureops/backend-go/api/model"
	baseservice "secureops/backend-go/api/service"
)

// TestAssetControllerHandlers verifies the asset controller request flow.
func TestAssetControllerHandlers(t *testing.T) {
	svc := &fakeAssetService{asset: sampleAsset(), assets: []model.Asset{sampleAsset()}}
	controller := NewAssetController(svc)

	t.Run("get assets", func(t *testing.T) {
		ec := newAssetContext(t, http.MethodGet, "/assets", "")
		controller.GetAssets(ec)
		if svc.getAllCalls != 1 {
			t.Fatal("expected GetAllAssets to be called")
		}
	})

	t.Run("create asset", func(t *testing.T) {
		ec := newAssetContext(t, http.MethodPost, "/assets", `{"name":"Asset 1","type":"Server","ipAddress":"10.0.0.10","owner":"IT","criticality":"High"}`)
		ec.Request.Header.Set("Content-Type", "application/json")
		controller.CreateAsset(ec)
		if svc.createCalls != 1 {
			t.Fatal("expected CreateAsset to be called")
		}
	})
}

type fakeAssetService struct {
	assets      []model.Asset
	asset       model.Asset
	err         error
	getAllCalls int
	createCalls int
}

func (f *fakeAssetService) GetAllAssets(ec *appcontext.GinContext) ([]model.Asset, error) {
	f.getAllCalls++
	return f.assets, f.err
}
func (f *fakeAssetService) GetAsset(ec *appcontext.GinContext, id int64) (model.Asset, error) {
	return f.asset, f.err
}
func (f *fakeAssetService) CreateAsset(ec *appcontext.GinContext, asset model.Asset) (model.Asset, error) {
	f.createCalls++
	return f.asset, f.err
}
func (f *fakeAssetService) UpdateAsset(ec *appcontext.GinContext, id int64, asset model.Asset) (model.Asset, error) {
	return f.asset, f.err
}
func (f *fakeAssetService) DeleteAsset(ec *appcontext.GinContext, id int64) (model.Asset, error) {
	return f.asset, f.err
}
func (f *fakeAssetService) AssignVulnerability(ec *appcontext.GinContext, assetID int64, vulnerabilityID int64) (model.Asset, error) {
	return f.asset, f.err
}
func (f *fakeAssetService) AssignVulnerabilityByCVE(ec *appcontext.GinContext, assetID int64, cveID string) (model.Asset, error) {
	return f.asset, f.err
}
func (f *fakeAssetService) RemoveVulnerability(ec *appcontext.GinContext, assetID int64, vulnerabilityID int64) (model.Asset, error) {
	return f.asset, f.err
}

var _ baseservice.AssetService = (*fakeAssetService)(nil)

// newAssetContext creates a test Gin context for asset controller tests.
func newAssetContext(t *testing.T, method string, target string, body string) *appcontext.GinContext {
	t.Helper()

	recorder := httptest.NewRecorder()
	ctx, _ := gin.CreateTestContext(recorder)
	req := httptest.NewRequest(method, target, nil)
	if body != "" {
		req.Body = io.NopCloser(strings.NewReader(body))
	}
	ctx.Request = req
	ec := appcontext.NewGinContext(ctx, "txn-123", nil)
	appcontext.SetGinContext(ctx, ec)
	return ec
}

// sampleAsset returns a reusable asset fixture.
func sampleAsset() model.Asset {
	return model.Asset{ID: 1, Name: "Asset 1", Type: "Server", IPAddress: "10.0.0.10", Owner: "IT", Criticality: "High"}
}

var _ = errors.New
var _ = dto.AssetRequest{}
