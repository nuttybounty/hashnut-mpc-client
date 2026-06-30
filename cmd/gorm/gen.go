package main

import (
	"gorm.io/driver/sqlite"
	"gorm.io/gen"
	"gorm.io/gorm"
	"strings"
)

func main() {
	// 连接数据库
	db, err := gorm.Open(sqlite.Open("../cli/keys.db"), &gorm.Config{})
	if err != nil {
		panic(err)
	}
	db = db.Debug()

	g := gen.NewGenerator(gen.Config{
		OutPath:      "../../storage/dal/query",
		ModelPkgPath: "../../storage/dal/model",
		Mode:         gen.WithDefaultQuery | gen.WithQueryInterface,
	})

	// 自定义 JSON 标签（首字母小写）
	g.WithJSONTagNameStrategy(func(columnName string) string {
		return strings.ToLower(columnName[:1]) + columnName[1:]
	})

	g.UseDB(db)
	tables := g.GenerateAllTable()
	g.ApplyBasic(tables...)
	g.Execute()
}
