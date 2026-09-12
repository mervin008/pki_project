module github.com/certpilot/certpilot/gateways/acme

go 1.26.6

replace github.com/certpilot/certpilot/pkg => ../../pkg

require (
	github.com/certpilot/certpilot/pkg v0.0.0
	golang.org/x/crypto v0.55.0
	google.golang.org/grpc v1.83.0
	google.golang.org/protobuf v1.36.12
)

require (
	golang.org/x/net v0.57.0 // indirect
	golang.org/x/sys v0.47.0 // indirect
	golang.org/x/text v0.41.0 // indirect
	google.golang.org/genproto/googleapis/rpc v0.0.0-20260526163538-3dc84a4a5aaa // indirect
)
