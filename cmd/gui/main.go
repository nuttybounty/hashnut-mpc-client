package main

import (
	"flag"
	"fmt"
	"hashnut-mpc-client/gui/pages"
	"hashnut-mpc-client/gui/service"
	"os"

	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/app"
)

// 编译时注入: go build -ldflags "-X main.buildEnv=mainnet -X main.version=v1.0.0"
var (
	buildEnv string
	version  string
)

var envURLs = map[string]string{
	"local":   "http://localhost:3022",
	"testnet": "https://testnet.hashnut.io",
	"mainnet": "https://defi.hashnut.io",
}

func main() {
	env := flag.String("env", "", "Override environment: local, testnet, mainnet")
	showVersion := flag.Bool("version", false, "Print version and exit")
	flag.Parse()

	if *showVersion {
		fmt.Printf("hashnut-mpc %s (env: %s)\n", version, buildEnv)
		os.Exit(0)
	}

	// 优先级: 启动参数 > 编译注入 > 默认mainnet
	target := *env
	if target == "" {
		target = buildEnv
	}
	if target == "" {
		target = "mainnet"
	}

	baseURL, ok := envURLs[target]
	if !ok {
		fmt.Fprintf(os.Stderr, "Unknown env: %s (valid: local, testnet, mainnet)\n", target)
		os.Exit(1)
	}

	svc := service.NewGUIService(baseURL)

	a := app.New()
	w := a.NewWindow("HashNut MPC Wallet")
	w.Resize(fyne.NewSize(900, 600))

	// 登录成功后切换到主页面
	showMain := func() {
		mainPage := pages.NewMainPage(svc, w)
		w.SetContent(mainPage.Build())
	}

	// 启动时显示登录页
	loginPage := pages.NewLoginPage(svc, w, showMain)
	w.SetContent(loginPage.Build())

	w.ShowAndRun()
}
