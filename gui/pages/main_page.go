package pages

import (
	"fmt"
	"hashnut-mpc-client/gui/service"

	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/container"
	"fyne.io/fyne/v2/dialog"
	"fyne.io/fyne/v2/widget"
)

// MainPage 解锁后的主页面
type MainPage struct {
	svc    *service.GUIService
	window fyne.Window
}

func NewMainPage(svc *service.GUIService, window fyne.Window) *MainPage {
	return &MainPage{svc: svc, window: window}
}

func (p *MainPage) Build() fyne.CanvasObject {
	walletLabel := widget.NewLabel("钱包: -")
	chains, _ := p.svc.ListChains()
	currentChain, _ := p.svc.GetCurrentChain()

	chainOptions := make([]string, len(chains))
	selectedIdx := 0
	for i, c := range chains {
		chainOptions[i] = fmt.Sprintf("%s (%s)", c.Chain, c.Currency)
		if c.Chain == currentChain {
			selectedIdx = i
		}
	}
	chainSelect := widget.NewSelect(chainOptions, func(selected string) {
		for _, c := range chains {
			label := fmt.Sprintf("%s (%s)", c.Chain, c.Currency)
			if label == selected {
				if err := p.svc.SwitchChain(c.Chain); err != nil {
					dialog.ShowError(err, p.window)
					return
				}
				p.refreshWalletLabel(walletLabel)
				return
			}
		}
	})
	if len(chainOptions) > 0 {
		chainSelect.SetSelectedIndex(selectedIdx)
	}

	p.refreshWalletLabel(walletLabel)
	topBar := container.NewHBox(chainSelect, widget.NewSeparator(), walletLabel)

	contentArea := container.NewStack()

	navButtons := []*widget.Button{
		widget.NewButton("钱包管理", func() {
			contentArea.Objects = []fyne.CanvasObject{p.buildWalletTab(walletLabel)}
			contentArea.Refresh()
		}),
		widget.NewButton("分账合约", func() {
			contentArea.Objects = []fyne.CanvasObject{p.buildSplitterTab()}
			contentArea.Refresh()
		}),
		widget.NewButton("批量创建地址", func() {
			contentArea.Objects = []fyne.CanvasObject{p.buildSetupTab()}
			contentArea.Refresh()
		}),
		widget.NewButton("Gas 评估", func() {
			contentArea.Objects = []fyne.CanvasObject{p.buildEstimateTab()}
			contentArea.Refresh()
		}),
		widget.NewButton("资金归集", func() {
			contentArea.Objects = []fyne.CanvasObject{p.buildClaimTab()}
			contentArea.Refresh()
		}),
		widget.NewButton("资金提现", func() {
			contentArea.Objects = []fyne.CanvasObject{p.buildReleaseTab()}
			contentArea.Refresh()
		}),
		widget.NewButton("回收手续费", func() {
			contentArea.Objects = []fyne.CanvasObject{p.buildSweepGasTab()}
			contentArea.Refresh()
		}),
		widget.NewButton("Nonce 诊断", func() {
			contentArea.Objects = []fyne.CanvasObject{p.buildNonceDiagnoseTab()}
			contentArea.Refresh()
		}),
	}

	sidebar := container.NewVBox()
	for _, btn := range navButtons {
		sidebar.Add(btn)
	}

	contentArea.Objects = []fyne.CanvasObject{p.buildWalletTab(walletLabel)}

	split := container.NewHSplit(sidebar, contentArea)
	split.SetOffset(0.2)

	return container.NewBorder(topBar, nil, nil, nil, split)
}

func (p *MainPage) refreshWalletLabel(walletLabel *widget.Label) {
	wallet, _ := p.svc.GetCurrentWallet()
	if wallet != nil && wallet.Address != "" {
		addr := wallet.Address
		if len(addr) > 14 {
			addr = addr[:8] + "..." + addr[len(addr)-4:]
		}
		walletLabel.SetText(fmt.Sprintf("钱包: %s", addr))
	} else {
		walletLabel.SetText("钱包: 未设置")
	}
}
