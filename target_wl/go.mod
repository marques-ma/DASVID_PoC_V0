module github.com/luish18/target-wl

require (
	github.com/dgrijalva/jwt-go v3.2.0+incompatible // indirect
	github.com/golang-jwt/jwt v3.2.2+incompatible // indirect
	github.com/joomcode/errorx v1.1.0 // indirect
	github.com/marco-developer/dasvid/poclib v1.0.0
	github.com/mattn/go-sqlite3 v1.14.11 // indirect
	github.com/spiffe/go-spiffe/v2 v2.0.0-beta.11 // indirect
	google.golang.org/grpc v1.33.2 // indirect
	gopkg.in/square/go-jose.v2 v2.4.1 // indirect
	modernc.org/sqlite v1.14.6 // indirect
)

replace github.com/marco-developer/dasvid/poclib v1.0.0 => ./poclib

go 1.16
