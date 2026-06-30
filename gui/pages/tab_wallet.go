package pages

import (
	"fmt"
	"hashnut-mpc-client/gui/service"

	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/container"
	"fyne.io/fyne/v2/dialog"
	"fyne.io/fyne/v2/widget"
)

// buildWalletTab 钱包管理 Tab
func (p *MainPage) buildWalletTab(walletLabel *widget.Label) fyne.CanvasObject {
	list := widget.NewList(
		func() int { return 0 },
		func() fyne.CanvasObject { return widget.NewLabel("") },
		func(id widget.ListItemID, obj fyne.CanvasObject) {},
	)

	var wallets []service.WalletInfo
	var refreshList func()
	refreshList = func() {
		var err error
		wallets, err = p.svc.ListWallets()
		if err != nil {
			return
		}
		list.Length = func() int { return len(wallets) }
		list.CreateItem = func() fyne.CanvasObject {
			addrLabel := widget.NewLabel("")
			typeLabel := widget.NewLabel("")
			setDefaultBtn := widget.NewButton("设为默认", nil)
			return container.NewHBox(addrLabel, typeLabel, setDefaultBtn)
		}
		list.UpdateItem = func(id widget.ListItemID, obj fyne.CanvasObject) {
			box := obj.(*fyne.Container)
			w := wallets[id]
			box.Objects[0].(*widget.Label).SetText(w.Address)
			if w.IsDefault {
				box.Objects[1].(*widget.Label).SetText(fmt.Sprintf("(%s) [默认]", w.ChainType))
				box.Objects[2].(*widget.Button).Hide()
			} else {
				box.Objects[1].(*widget.Label).SetText(fmt.Sprintf("(%s)", w.ChainType))
				btn := box.Objects[2].(*widget.Button)
				btn.Show()
				addr := w.Address
				btn.OnTapped = func() {
					if err := p.svc.SwitchWallet(addr); err != nil {
						dialog.ShowError(err, p.window)
						return
					}
					refreshList()
					p.refreshWalletLabel(walletLabel)
				}
			}
		}
		list.Refresh()
	}
	refreshList()

	importBtn := widget.NewButton("导入钱包", func() {
		chainTypeEntry := widget.NewSelect([]string{"evm", "tron"}, nil)
		chainTypeEntry.SetSelected("evm")
		privKeyEntry := widget.NewPasswordEntry()
		privKeyEntry.SetPlaceHolder("输入私钥 (hex)")

		items := []*widget.FormItem{
			widget.NewFormItem("链类型", chainTypeEntry),
			widget.NewFormItem("私钥", privKeyEntry),
		}

		dialog.ShowForm("导入钱包", "导入", "取消", items, func(ok bool) {
			if !ok {
				return
			}
			privKey := privKeyEntry.Text
			privKeyEntry.SetText("")

			if err := p.svc.ImportWallet(chainTypeEntry.Selected, privKey); err != nil {
				dialog.ShowError(err, p.window)
				return
			}
			dialog.ShowInformation("成功", "钱包导入成功", p.window)
			refreshList()
			p.refreshWalletLabel(walletLabel)
		}, p.window)
	})

	return container.NewBorder(
		container.NewHBox(importBtn),
		nil, nil, nil,
		list,
	)
}
