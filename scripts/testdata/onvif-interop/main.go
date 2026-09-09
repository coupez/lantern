package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"github.com/GyeongHoKim/onvif-simulator/internal/onvif/devicesvc"
	"github.com/coupez/lantern/pkg/onvif"
	"net/http"
	"net/http/httptest"
	"os"
)

type fixtureProvider struct{ devicesvc.Provider }

func (fixtureProvider) DeviceInfo(context.Context) (devicesvc.DeviceInfo, error) {
	return devicesvc.DeviceInfo{Manufacturer: "Example", Model: "Camera 7", Firmware: "1.2.3", Serial: "synthetic-serial", HardwareID: "synthetic-hardware"}, nil
}
func main() {
	handler := devicesvc.NewHandler(fixtureProvider{})
	request := httptest.NewRequest(http.MethodPost, "http://127.0.0.1"+devicesvc.DeviceServicePath, bytes.NewReader(onvif.Request()))
	request.Header.Set("Content-Type", `application/soap+xml; charset=utf-8; action="`+onvif.Action+`"`)
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != 200 {
		panic(fmt.Sprintf("HTTP %d: %s", response.Code, response.Body.String()))
	}
	fields, err := onvif.ParseResponse(response.Body.Bytes())
	if err != nil {
		panic(err)
	}
	if len(fields) != 3 || fields["Manufacturer"] != "Example" || fields["Model"] != "Camera 7" || fields["FirmwareVersion"] != "1.2.3" {
		panic(fmt.Sprintf("unexpected fields: %v", fields))
	}
	json.NewEncoder(os.Stdout).Encode(map[string]any{"status": "passed", "http_status": response.Code, "response_bytes": response.Body.Len(), "content_type": response.Header().Get("Content-Type"), "fields": fields})
}
