package pages

import (
	"context"
	"fmt"
	"hashnut-mpc-client/gui/service"

	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/container"
	"fyne.io/fyne/v2/dialog"
	"fyne.io/fyne/v2/widget"
)

// buildSplitterTab 分账合约 Tab
func (p *MainPage) buildSplitterTab() fyne.CanvasObject {
	list := widget.NewList(
		func() int { return 0 },
		func() fyne.CanvasObject { return widget.NewLabel("") },
		func(id widget.ListItemID, obj fyne.CanvasObject) {},
	)

	activateLog := widget.NewMultiLineEntry()
	activateLog.Wrapping = fyne.TextWrapWord
	activateLog.TextStyle = fyne.TextStyle{Monospace: true}

	appendActivateLog := func(msg string) {
		fyne.Do(func() {
			activateLog.SetText(activateLog.Text + msg + "\n")
		})
	}

	var splitters []service.SplitWalletInfo
	var activatingAddr string

	var refreshList func()
	refreshList = func() {
		// 进入时自动从服务端同步
		chain, _ := p.svc.GetCurrentChain()
		if chain != "" {
			_ = p.svc.FetchSplitWallets(chain)
		}

		var err error
		splitters, err = p.svc.ListSplitWalletsByChainAndMerchant()
		if err != nil {
			return
		}

		list.Length = func() int { return len(splitters) }
		list.CreateItem = func() fyne.CanvasObject {
			addrLabel := widget.NewLabel("")
			stateLabel := widget.NewLabel("")
			activateBtn := widget.NewButton("激活", nil)
			upgradeBtn := widget.NewButton("升级", nil)
			return container.NewHBox(addrLabel, stateLabel, activateBtn, upgradeBtn)
		}
		list.UpdateItem = func(id widget.ListItemID, obj fyne.CanvasObject) {
			box := obj.(*fyne.Container)
			sw := splitters[id]
			box.Objects[0].(*widget.Label).SetText(truncAddr(sw.Address))
			box.Objects[1].(*widget.Label).SetText(fmt.Sprintf("[%s]", stateToString(sw.State)))

			activateBtn := box.Objects[2].(*widget.Button)
			upgradeBtn := box.Objects[3].(*widget.Button)

			// 只有 PENDING_MANAGER 和 MANAGER_GENERATED 状态显示激活按钮
			if sw.State == 4 || sw.State == 5 {
				activateBtn.Show()
				upgradeBtn.Hide()
				addr := sw.Address
				activateBtn.OnTapped = func() {
					if activatingAddr != "" {
						dialog.ShowInformation("提示", "正在激活中，请等待", p.window)
						return
					}
					activatingAddr = addr
					activateLog.SetText("")
					activateBtn.Disable()
					go func() {
						defer fyne.Do(func() {
							activatingAddr = ""
							activateBtn.Enable()
							refreshList()
						})
						ctx := context.Background()
						if err := p.svc.ActivateSplitWallet(ctx, addr, appendActivateLog); err != nil {
							appendActivateLog(fmt.Sprintf("ERROR: %v", err))
						}
					}()
				}
			} else if sw.State == 7 { // ACTIVE
				activateBtn.Hide()
				upgradeBtn.Show()
				addr := sw.Address
				swChain := sw.Chain
				upgradeBtn.OnTapped = func() {
					implEntry := widget.NewEntry()
					implEntry.SetPlaceHolder("新逻辑合约地址 (0x...)")
					dlg := dialog.NewForm("升级逻辑合约", "确认升级", "取消",
						[]*widget.FormItem{
							widget.NewFormItem("Implementation", implEntry),
						},
						func(ok bool) {
							if !ok || implEntry.Text == "" {
								return
							}
							activateLog.SetText("")
							upgradeBtn.Disable()
							go func() {
								defer fyne.Do(func() {
									upgradeBtn.Enable()
									refreshList()
								})
								ctx := context.Background()
								txID, err := p.svc.UpgradeContract(ctx, swChain, addr, implEntry.Text, appendActivateLog)
								if err != nil {
									appendActivateLog(fmt.Sprintf("ERROR: %v", err))
								} else {
									appendActivateLog(fmt.Sprintf("升级成功! txId=%s", txID))
								}
							}()
						}, p.window)
					dlg.Resize(fyne.NewSize(500, 200))
					dlg.Show()
				}
			} else {
				activateBtn.Hide()
				upgradeBtn.Hide()
			}
		}
		list.Refresh()
	}
	refreshList()

	refreshBtn := widget.NewButton("刷新", func() {
		refreshList()
	})

	return container.NewBorder(
		container.NewVBox(
			container.NewHBox(refreshBtn),
		),
		nil, nil, nil,
		container.NewVSplit(list, container.NewScroll(activateLog)),
	)
}
