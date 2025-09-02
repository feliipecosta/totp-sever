package models

type Account struct {
	Name   string `json:"name"`
	Secret string `json:"secret"`
}

type TemplateData struct {
	Accounts     []CodeDisplay
	Error        string
	SessionToken string
}

type CodeDisplay struct {
	Name string
	Code string
}