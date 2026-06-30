// Package pages 包含所有 GUI 页面。
// 每个页面只做 UI 展示和用户交互，业务逻辑通过 service.GUIService 调用。
package pages

import (
	"hashnut-mpc-client/gui/service"

	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/container"
	"fyne.io/fyne/v2/dialog"
	"fyne.io/fyne/v2/layout"
	"fyne.io/fyne/v2/widget"
)

// LoginPage 密码登录/设置页面
type LoginPage struct {
	svc      *service.GUIService
	window   fyne.Window
	onLogin  func() // 登录成功后回调，切换到主页面
}

func NewLoginPage(svc *service.GUIService, window fyne.Window, onLogin func()) *LoginPage {
	return &LoginPage{svc: svc, window: window, onLogin: onLogin}
}

func (p *LoginPage) Build() fyne.CanvasObject {
	if p.svc.HasPassword() {
		return p.buildVerifyView()
	}
	return p.buildSetupView()
}

// buildSetupView 首次设置密码
func (p *LoginPage) buildSetupView() fyne.CanvasObject {
	title := widget.NewLabel("首次运行，请设置访问密码")
	title.Alignment = fyne.TextAlignCenter
	title.TextStyle = fyne.TextStyle{Bold: true}

	passwordEntry := widget.NewPasswordEntry()
	passwordEntry.SetPlaceHolder("输入密码")

	confirmEntry := widget.NewPasswordEntry()
	confirmEntry.SetPlaceHolder("确认密码")

	statusLabel := widget.NewLabel("")

	submitBtn := widget.NewButton("设置密码", func() {
		pwd := passwordEntry.Text
		confirm := confirmEntry.Text

		if pwd == "" {
			statusLabel.SetText("密码不能为空")
			return
		}
		if pwd != confirm {
			statusLabel.SetText("两次输入的密码不一致")
			return
		}

		statusLabel.SetText("正在设置...")
		// 安全：提交后立即清空输入框
		passwordEntry.SetText("")
		confirmEntry.SetText("")

		go func() {
			if err := p.svc.SetPassword(pwd); err != nil {
				fyne.Do(func() {
					statusLabel.SetText("设置失败: " + err.Error())
				})
				return
			}
			fyne.Do(func() {
				statusLabel.SetText("密码设置成功")
				p.onLogin()
			})
		}()
	})

	return container.NewVBox(
		layout.NewSpacer(),
		container.NewCenter(
			container.NewVBox(
				title,
				widget.NewLabel(""),
				widget.NewFormItem("密码", passwordEntry).Widget,
				widget.NewFormItem("确认密码", confirmEntry).Widget,
				widget.NewLabel(""),
				submitBtn,
				statusLabel,
			),
		),
		layout.NewSpacer(),
	)
}

// buildVerifyView 验证密码登录
func (p *LoginPage) buildVerifyView() fyne.CanvasObject {
	title := widget.NewLabel("MPC 钱包")
	title.Alignment = fyne.TextAlignCenter
	title.TextStyle = fyne.TextStyle{Bold: true}

	subtitle := widget.NewLabel("请输入密码解锁")
	subtitle.Alignment = fyne.TextAlignCenter

	passwordEntry := widget.NewPasswordEntry()
	passwordEntry.SetPlaceHolder("输入密码")

	statusLabel := widget.NewLabel("")

	var submitBtn *widget.Button
	submitBtn = widget.NewButton("解锁", func() {
		pwd := passwordEntry.Text
		if pwd == "" {
			statusLabel.SetText("请输入密码")
			return
		}

		submitBtn.Disable()
		statusLabel.SetText("正在验证...")
		// 安全：提交后立即清空输入框
		passwordEntry.SetText("")

		go func() {
			if err := p.svc.VerifyPassword(pwd); err != nil {
				fyne.Do(func() {
					submitBtn.Enable()
					statusLabel.SetText(err.Error())
				})
				return
			}
			fyne.Do(func() {
				p.onLogin()
			})
		}()
	})

	// 支持回车提交
	passwordEntry.OnSubmitted = func(_ string) {
		submitBtn.OnTapped()
	}

	return container.NewVBox(
		layout.NewSpacer(),
		container.NewCenter(
			container.NewVBox(
				title,
				subtitle,
				widget.NewLabel(""),
				passwordEntry,
				widget.NewLabel(""),
				submitBtn,
				statusLabel,
			),
		),
		layout.NewSpacer(),
	)
}

// ShowError 显示错误弹窗
func ShowError(err error, window fyne.Window) {
	dialog.ShowError(err, window)
}

// ShowInfo 显示信息弹窗
func ShowInfo(title, message string, window fyne.Window) {
	dialog.ShowInformation(title, message, window)
}
