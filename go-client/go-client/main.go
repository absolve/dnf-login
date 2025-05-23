package main

import (
	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/app"
	"fyne.io/fyne/v2/container"
	"fyne.io/fyne/v2/widget"
)

func main() {
	a := app.New()
	w := a.NewWindow("DNF台服登录器")

	input := widget.NewEntry()
	input.SetPlaceHolder("输入账号")
	pwd := widget.NewPasswordEntry()
	pwd.SetPlaceHolder("输入密码")
	form := &widget.Form{
		Items: []*widget.FormItem{
			{Text: "账号", Widget: input},
			{Text: "密码", Widget: pwd}},
		OnSubmit: func() {

		},
		SubmitText: "登录",
	}

	createBtn := widget.NewButton("新建账号", func() {

	})
	forgetBtn := widget.NewButton("忘记密码", func() {

	})
	btnContainer := container.NewHBox(createBtn, forgetBtn)

	w.SetContent(container.NewVBox(
		btnContainer,
		form,
	))
	w.Resize(fyne.NewSize(340, 200))
	w.CenterOnScreen()
	w.ShowAndRun()
}
