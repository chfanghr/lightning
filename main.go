package main

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"flag"
	"fmt"
	qrcodeTerminal "github.com/Baozisoftware/qrcode-terminal-go"
	mirai "github.com/Mrs4s/MiraiGo/client"
	"github.com/Mrs4s/MiraiGo/message"
	log "github.com/sirupsen/logrus"
	"github.com/tuotoo/qrcode"
	asciiArt "github.com/yinghau76/go-ascii-art"
	tb "gopkg.in/tucnak/telebot.v2"
	"image"
	"io/ioutil"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"
)

func precondition(condition bool) {
	if !condition {
		panic("precondition failure")
	}
}

func preconditionWithMessage(condition bool, message string) {
	if !condition {
		panic(fmt.Sprintf("precondition failure: %s", message))
	}
}

func preconditionNoError(err error) {
	if err != nil {
		panic(fmt.Sprintf("precondition failure: unexpected error %v", err))
	}
}

//func preconditionFailure() {
//	panic("precondition failure")
//}

type Config struct {
	QQ struct {
		LoginViaQrCode bool   `json:"login_via_qr_code,omitempty"`
		Account        int64  `json:"account,omitempty"`
		Password       string `json:"password,omitempty"`

		GroupId int64 `json:"group_id"`
	} `json:"qq"`

	Telegram struct {
		BotToken string `json:"bot_token"`

		MyId      int     `json:"my_id"`
		ChatId    int64   `json:"chat_id"`
		FilterIds []int64 `json:"filter_ids,omitempty"`
	} `json:"telegram"`

	Network struct {
		Proxy string `json:"proxy,omitempty"`
	} `json:"network,omitempty"`

	Verbose  bool `json:"verbose,omitempty"`
	Headless bool `json:"headless,omitempty"`
}

func NewConfigFromFile(filename string) (*Config, error) {
	content, err := ioutil.ReadFile(filename)
	if err != nil {
		return nil, fmt.Errorf("reading %v: %w", filename, err)
	}
	config := Config{}
	if json.Unmarshal(content, &config) != nil {
		return nil, fmt.Errorf("decoding %v: %w", filename, err)
	}

	return &config, nil
}

type Service struct {
	config *Config

	tgBot    *tb.Bot
	qqClient *mirai.QQClient

	logger *log.Logger

	context    context.Context
	cancelFunc context.CancelFunc

	tgChat *tb.Chat
}

func NewServiceFromConfig(config *Config, handleSignals bool) (*Service, error) {
	s := &Service{
		config: config,
		logger: log.New(),
	}

	if config.Verbose {
		s.logger.SetLevel(log.DebugLevel)
	}

	if err := s.setupTgBot(); err != nil {
		return nil, err
	}

	if err := s.setupQQClient(); err != nil {
		return nil, err
	}

	s.context, s.cancelFunc = context.WithCancel(context.TODO())

	if handleSignals {
		s.handleSignals()
	}

	return s, nil
}

const QQDeviceInformationFilename = "device.json"
const QQDeviceProtocol = mirai.MacOS

func (s *Service) setupTgBot() error {

	var tgBotHttpClient *http.Client

	if s.config.Network.Proxy != "" {
		proxyUrl, err := url.Parse(s.config.Network.Proxy)
		if err != nil {
			return err
		}
		tgBotHttpClient = &http.Client{
			Transport: &http.Transport{
				Proxy: http.ProxyURL(proxyUrl),
			},
		}
	}

	var err error

	s.tgBot, err = tb.NewBot(tb.Settings{
		Token: s.config.Telegram.BotToken,
		Poller: &tb.LongPoller{
			Limit:   10,
			Timeout: 6 * time.Second,
			AllowedUpdates: []string{
				"message",
			},
		},
		//Verbose: s.config.Verbose,
		Client: tgBotHttpClient,
	})

	if err != nil {
		return fmt.Errorf("failed to create telegram bot: %w", err)
	}

	s.tgChat, err = s.tgBot.ChatByID(fmt.Sprintf("%v", s.config.Telegram.ChatId))
	if err != nil {
		return fmt.Errorf("failed to find telegram chat: %w", err)
	}

	s.tgBot.Handle(tb.OnText, func(m *tb.Message) {
		if m != nil &&
			m.Chat.ID == s.config.Telegram.ChatId &&
			!m.Sender.IsBot {
			s.logger.Debugf("telegram message: message: %s, sender: %d\n", m.Text, m.Sender.ID)
			go func() {
				var groupMessage *message.GroupMessage
				for i := 0; i < 5; i++ {
					groupMessage = s.qqClient.SendGroupMessage(s.config.QQ.GroupId,
						&message.SendingMessage{Elements: []message.IMessageElement{
							&message.TextElement{
								Content: fmt.Sprintf("forwarded by lightning from telegram: \n%s %s said: %s", m.Sender.FirstName, m.Sender.LastName, m.Text),
							},
						}})
					if groupMessage.Id != -1 {
						s.logger.Debugf("qq group message sent, id: %v\n", groupMessage.Id)
						return
					}
				}
				s.logger.Errorf("failed to send qq group message")
			}()

		}
	})

	return nil
}

func (s *Service) loadQQDeviceInformation() {
	mirai.SystemDeviceInfo.Protocol = QQDeviceProtocol

	if _, err := os.Stat(QQDeviceInformationFilename); err == nil {
		if content, err := ioutil.ReadFile(QQDeviceInformationFilename); err == nil {
			if mirai.SystemDeviceInfo.ReadJson(content) == nil {
				return
			}
		}
	}

	mirai.GenRandomDevice()
	err := ioutil.WriteFile(QQDeviceInformationFilename, mirai.SystemDeviceInfo.ToJson(), os.FileMode(0755))
	if err != nil {
		s.logger.Warningf("failed to presistent device information: %v", err)
	}
	return
}

func (s *Service) loginQQAccountViaQR() error {
	s.loadQQDeviceInformation()
generateAndPresentQrCode:
	resp, err := s.qqClient.FetchQRCode()
	if err != nil {
		return fmt.Errorf("failed to fetch qr code: %w", err)
	}

	loginQr, err := qrcode.Decode(bytes.NewReader(resp.ImageData))
	preconditionWithMessage(err == nil, "decoding login qr code")

	fmt.Println()
	fmt.Println("Scan this qr code to login on mobile qq app:")
	//goland:noinspection GoNilness
	qrcodeTerminal.New().Get(loginQr.Content).Print()
	fmt.Println()

	var prevStatus mirai.QRCodeLoginState

	for {
		qrStatus, err := s.qqClient.QueryQRCodeStatus(resp.Sig)

		if err != nil {
			return fmt.Errorf("failed to query code ststus: %w", err)
		}

		if qrStatus == nil {
			continue
		}

		if prevStatus == qrStatus.State {
			continue
		}
		prevStatus = qrStatus.State

		switch qrStatus.State {
		case mirai.QRCodeTimeout:
			goto generateAndPresentQrCode
		case mirai.QRCodeCanceled:
			continue
		case mirai.QRCodeWaitingForConfirm:
			fmt.Println("Please confirm on your phone")
			continue
		case mirai.QRCodeConfirmed:
			loginResp, err := s.qqClient.QRCodeLogin(qrStatus.LoginInfo)
			if err != nil {
				return fmt.Errorf("failed to login: %w", err)
			}
			return s.handleQQLoginResponse(loginResp)
		}
	}
}

func (s *Service) handleQQLoginResponse(loginResp *mirai.LoginResponse) (loginErr error) {
	var consoleInput *bufio.Reader

	if !s.config.Headless {
		consoleInput = bufio.NewReader(os.Stdin)
	}

	for loginErr != nil || !loginResp.Success {
		if loginErr != nil {
			return fmt.Errorf("cannot login qq acount: %w", loginErr)
		}

		switch loginResp.Error {
		case mirai.UnsafeDeviceError, mirai.TooManySMSRequestError, mirai.OtherLoginError,
			mirai.UnknownLoginError, mirai.SliderNeededError:
			return fmt.Errorf("unhandlable login error: %v", loginResp.Error)
		}

		if s.config.Headless {
			return fmt.Errorf("can't authenticate on a headless device")
		}

		switch loginResp.Error {
		case mirai.NeedCaptcha:
			img, _, err := image.Decode(bytes.NewReader(loginResp.CaptchaImage))
			preconditionWithMessage(err == nil, "failed to decode captcha image")

			asciiPresentation := asciiArt.New("Captcha image", img)
			fmt.Println()
			fmt.Println(asciiPresentation.Title)
			fmt.Println(asciiPresentation.Art)
			fmt.Println()
			fmt.Print("Type captcha code and hit enter: ")

			//goland:noinspection GoNilness
			text, err := consoleInput.ReadString('\n')
			precondition(err == nil)

			loginResp, loginErr = s.qqClient.SubmitCaptcha(strings.TrimRight(text, "\r\n"), loginResp.CaptchaSign)
		case mirai.SMSNeededError:
			if !s.qqClient.RequestSMS() {
				return fmt.Errorf("unable to request sms code")
			}
			fmt.Printf("sms code has been sent to: %v\n", loginResp.SMSPhone)
			fmt.Print("Type sms code and hit enter: ")

			//goland:noinspection GoNilness
			text, err := consoleInput.ReadString('\n')
			precondition(err == nil)

			loginResp, loginErr = s.qqClient.SubmitSMS(text)
		}
	}

	s.logger.Infoln("qq login success")
	return nil
}

func (s *Service) loginQQAccountUsingPassword() error {
	s.loadQQDeviceInformation()
	loginResp, err := s.qqClient.Login()

	if err != nil {
		return fmt.Errorf("cannot login qq account: %w", err)
	}

	return s.handleQQLoginResponse(loginResp)
}

func (s *Service) setupQQClient() error {
	var qqLoginError error

	if s.config.QQ.LoginViaQrCode {
		s.qqClient = mirai.NewClientEmpty()
		qqLoginError = s.loginQQAccountViaQR()
	} else {
		s.qqClient = mirai.NewClient(s.config.QQ.Account, s.config.QQ.Password)
		qqLoginError = s.loginQQAccountUsingPassword()
	}

	if qqLoginError != nil {
		return fmt.Errorf("failed to login qq account: %w", qqLoginError)
	}

	s.qqClient.OnGroupMessage(s.onQQGroupMessage)
	s.qqClient.OnLog(s.onQQLog)
	s.qqClient.OnSelfGroupMessage(s.onQQGroupMessage)

	return nil
}

func (s *Service) onQQLog(client *mirai.QQClient, e *mirai.LogEvent) {
	precondition(client == s.qqClient)
	var logLevel log.Level

	switch e.Type {
	case "INFO":
		logLevel = log.InfoLevel
	case "ERROR":
		logLevel = log.ErrorLevel
	case "DEBUG":
		logLevel = log.DebugLevel
	}

	s.logger.Logf(logLevel, "qq client: %v\n", e.Message)
}

func (s *Service) onQQGroupMessage(client *mirai.QQClient, message *message.GroupMessage) {
	precondition(s.qqClient == client)
	s.logger.Debugf("qq group message: %v", message.ToString())
	if message.GroupCode != s.config.QQ.GroupId || message.Sender.Uin == s.qqClient.Uin {
		return
	}

	_, err := s.tgBot.Send(s.tgChat, fmt.Sprintf("forwarded by lighting from qq:\n%s(%s) said %s", message.Sender.CardName, message.Sender.Nickname, message.ToString()))
	if err != nil {
		s.logger.Errorf("failed to forward message from qq to telegram: %v", err)
	}
}

func (s *Service) Stop() error {
	s.cancelFunc()

	s.tgBot.Stop()
	s.qqClient.Disconnect()

	return nil
}

func (s *Service) Run() {
	s.tgBot.Start()
	<-s.context.Done()
}

func (s *Service) handleSignals() {
	signalChannel := make(chan os.Signal)
	signal.Notify(signalChannel, syscall.SIGKILL, syscall.SIGABRT, syscall.SIGINT, syscall.SIGTERM)

	go func() {
		for {
			select {
			case <-signalChannel:
				_ = s.Stop()
				return
			case <-s.context.Done():
				return
			}
		}
	}()
}

var configFilename = flag.String("c", "config.json", "configuration file to be used")

func main() {
	flag.Parse()

	config, err := NewConfigFromFile(*configFilename)
	preconditionNoError(err)

	service, err := NewServiceFromConfig(config, true)
	preconditionNoError(err)

	service.Run()
}
