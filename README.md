# casbin-bun-adapter

> Bun adapter for Casbin

## Installation
```sh
go get github.com/cuipeiyu/casbin-bun-adapter

```

## How to use?
```go
package main

import (
	bunadapter "github.com/cuipeiyu/casbin-bun-adapter"
)

var driverName = "pg" // Your can also use mysql and mssql
var sourceName = "user=postgres password=postgres host=localhost port=5432 database=casbin sslmode=disable"
var schemaName = "public"
var tableName = "casbin_rule"

func main() {
	a, err := bunadapter.NewAdapter(
		driverName,
		sourceName,
		bunadapter.WithTableName(schemaName, tableName),
	)
	handleError(err)
}

```

**OR**

```go
package main

import (
	"database/sql"
	"fmt"

	_ "github.com/jackc/pgx/v4/stdlib"

	bunadapter "github.com/cuipeiyu/casbin-bun-adapter"
)

var driverName = "pg" // Your can also use mysql and mssql
var sourceName = "user=postgres password=postgres host=localhost port=5432 database=casbin sslmode=disable" // demo for postgresql
var schemaName = "public"
var tableName = "casbin_rule"

func main() {
	// new sql driver
	db, err := sql.Open("pgx", sourceName)
	handleError(err)
	defer db.Close()

	// use custome driver
	a, err := bunadapter.NewAdapterWithClient(
		db,
		bunadapter.WithTableName(schemaName, tableName),
	)
	handleError(err)
}

```

## License

MIT
