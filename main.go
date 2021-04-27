package main

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"flag"
	"fmt"
	qrcodeTerminal "github.com/Baozisoftware/qrcode-terminal-go"
	"github.com/Mrs4s/MiraiGo/binary"
	mirai "github.com/Mrs4s/MiraiGo/client"
	miraiMessage "github.com/Mrs4s/MiraiGo/message"
	"github.com/go-redis/redis/v8"
	log "github.com/sirupsen/logrus"
	"github.com/tuotoo/qrcode"
	asciiArt "github.com/yinghau76/go-ascii-art"
	tb "gopkg.in/tucnak/telebot.v2"
	"image"
	_ "image/jpeg"
	"io/ioutil"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"path"
	"strings"
	"sync"
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

func preconditionFailureWithMessage(message string) {
	panic(fmt.Sprintf("precondition failure: %s", message))
}

func isFileOrFolderExists(path string) bool {
	_, err := os.Stat(path)
	return err == nil || os.IsExist(err)
}

type Config struct {
	QQ struct {
		LoginViaQrCode bool   `json:"login_via_qr_code,omitempty"`
		Account        int64  `json:"account,omitempty"`
		Password       string `json:"password,omitempty"`

		GroupId int64 `json:"group_id"`
	} `json:"qq"`

	Telegram struct {
		BotToken string `json:"bot_token"`

		ChatId int64 `json:"chat_id"`
	} `json:"telegram"`

	Network struct {
		Proxy string `json:"proxy,omitempty"`
	} `json:"network,omitempty"`

	Debug struct {
		Verbose              bool `json:"verbose,omitempty"`
		QQDontFilterYourself bool `json:"qq_dont_filter_yourself"`
	} `json:"debug"`

	Redis struct {
		Url string `json:"redis_url,omitempty"`

		Address  string `json:"address,omitempty"`
		DB       int    `json:"db,omitempty"`
		Username string `json:"username,omitempty"`
		Password string `json:"password,omitempty"`
	} `json:"redis,omitempty"`

	Headless bool `json:"headless,omitempty"`

	UserDataFolder string `json:"user_data_folder,omitempty"`
}

const DefaultUserDataFolder = "./userdata"

func NewConfigFromFile(filename string) (*Config, error) {
	content, err := ioutil.ReadFile(filename)
	if err != nil {
		return nil, fmt.Errorf("reading %v: %w", filename, err)
	}
	config := Config{}
	if json.Unmarshal(content, &config) != nil {
		return nil, fmt.Errorf("decoding %v: %w", filename, err)
	}

	if config.UserDataFolder == "" {
		config.UserDataFolder = DefaultUserDataFolder
	}
	return &config, nil
}

type Service struct {
	config *Config

	telegramBot *tb.Bot
	qqClient    *mirai.QQClient

	logger *log.Logger

	context    context.Context
	cancelFunc context.CancelFunc

	telegramChat *tb.Chat

	qqToSendMessageChannel chan *qqToSendMessage

	workerWaitGroup sync.WaitGroup

	redisClient *redis.Client
}

type qqToSendMessage struct {
	originalTelegramMessageId int
	toSend                    interface{}
}

func NewServiceFromConfig(config *Config, handleSignals bool) (*Service, error) {
	s := &Service{
		config: config,
		logger: log.New(),
	}

	if config.Debug.Verbose {
		s.logger.SetLevel(log.DebugLevel)
	} else {
		s.logger.SetLevel(log.InfoLevel)
	}

	s.logger.Infoln("constructing service")

	if err := s.makeUserDataDirectoryIfNeeded(); err != nil {
		return nil, err
	}

	if err := s.reportIfError(s.setupTelegramBot()); err != nil {
		return nil, err
	}
	if err := s.reportIfError(s.setupQQClient()); err != nil {
		return nil, err
	}

	s.context, s.cancelFunc = context.WithCancel(context.TODO())

	if handleSignals {
		s.handleSignals()
	}

	s.qqToSendMessageChannel = make(chan *qqToSendMessage, 100)

	if err := s.setupRedisDatabase(); err != nil {
		s.redisClient = nil
		log.Warningf("failed to setup redis: %v", err)
	}

	return s, nil
}

func (s *Service) setupRedisDatabase() (err error) {
	var options *redis.Options

	if s.config.Redis.Url != "" {
		options, err = redis.ParseURL(s.config.Redis.Url)
		if err != nil {
			return fmt.Errorf("parse redis url: %w", err)
		}
	} else if s.config.Redis.Address != "" {
		options = &redis.Options{
			Username: s.config.Redis.Username,
			Password: s.config.Redis.Password,
			Addr:     s.config.Redis.Address,
			DB:       s.config.Redis.DB,
		}
	} else {
		return fmt.Errorf("no redis configuration given")
	}

	s.redisClient = redis.NewClient(options)

	serverInfo, err := s.redisClient.Do(s.redisClient.Context(), "INFO").Result()
	if err != nil {
		return fmt.Errorf("failed to get redis server information: %w", err)
	}
	log.Infof("redis server connected: %v", serverInfo.(string))
	return nil
}

func (s *Service) qqMessageSender() {
	s.logger.Infof("qq message sender started")

	sendMessage := func(toSend *qqToSendMessage) {
		var groupMessage *miraiMessage.GroupMessage
		var message *miraiMessage.SendingMessage
		var err error

		switch toSend.toSend.(type) {
		case *miraiMessage.SendingMessage:
			message = toSend.toSend.(*miraiMessage.SendingMessage)
		case func() (*miraiMessage.SendingMessage, error):
			generatorFunc := toSend.toSend.(func() (*miraiMessage.SendingMessage, error))
			for i := 0; i < TryLimit; i++ {
				message, err = generatorFunc()
				if err != nil {
					s.logger.Warningf("failed to generate qq message: %v\n", err)
				} else {
					break
				}
			}
			if err != nil {
				s.logger.Errorf("failed to generate qq message: %v\n", err)
				goto failure
			}
		}

		for i := 0; i < TryLimit; i++ {
			groupMessage = s.qqClient.SendGroupMessage(s.config.QQ.GroupId, message)
			if groupMessage == nil || groupMessage.Id == -1 {
				s.logger.Warningln("failed to send qq group message")
				time.Sleep(time.Second)
			} else {
				return
			}
		}

	failure:
		s.logger.Errorf("failed to forward telegram message (%v) to qq\n", toSend.originalTelegramMessageId)
	}

	for {
		select {
		case <-s.context.Done():
			for msg := range s.qqToSendMessageChannel {
				sendMessage(msg)
			}
			close(s.qqToSendMessageChannel)
			s.workerWaitGroup.Done()
			return
		case msg := <-s.qqToSendMessageChannel:
			sendMessage(msg)
		}
	}
}

func (s *Service) makeUserDataDirectoryIfNeeded() error {
	if !isFileOrFolderExists(s.config.UserDataFolder) {
		s.logger.Infoln("user data folder does not exist, creating it")
		if err := os.Mkdir(s.config.UserDataFolder, 0700); err != nil {
			return s.reportIfError(fmt.Errorf("failed to create userdata directory: %w", err))
		}
	}
	return nil
}

func (s *Service) reportIfError(err error) error {
	if err != nil {
		s.logger.Errorln(err)
	}
	return err
}

const QQDeviceInformationFilename = "device.json"
const QQDeviceProtocol = mirai.MacOS

const TryLimit = 10

func (s *Service) userDataPath(filename string) string {
	return path.Join(s.config.UserDataFolder, filename)
}

func (s *Service) setupTelegramBot() error {
	s.logger.Infoln("creating telegram bot")

	var tgBotHttpClient *http.Client

	if s.config.Network.Proxy != "" {
		s.logger.Infof("using proxy: %v", s.config.Network.Proxy)
		proxyUrl, err := url.Parse(s.config.Network.Proxy)
		if err != nil {
			return fmt.Errorf("failed to parse proxy url: %w", err)
		}
		tgBotHttpClient = &http.Client{
			Transport: &http.Transport{
				Proxy: http.ProxyURL(proxyUrl),
			},
		}
	}

	var err error

	botPoller := tb.NewMiddlewarePoller(&tb.LongPoller{
		Limit:   10,
		Timeout: 6 * time.Second,
		AllowedUpdates: []string{
			"message",
		},
	}, func(update *tb.Update) bool {
		if update.Message == nil {
			return false
		}
		return !update.Message.Sender.IsBot &&
			update.Message.Chat.ID == s.config.Telegram.ChatId
	})

	s.telegramBot, err = tb.NewBot(tb.Settings{
		Token:   s.config.Telegram.BotToken,
		Poller:  botPoller,
		Verbose: s.config.Debug.Verbose,
		Client:  tgBotHttpClient,
		Reporter: func(err error) {
			s.logger.Errorf("telebot: %v", err)
		},
	})

	if err != nil {
		return fmt.Errorf("failed to create telegram bot: %w", err)
	}

	s.logger.Infoln("telegram bot created")

	s.telegramChat, err = s.telegramBot.ChatByID(fmt.Sprintf("%v", s.config.Telegram.ChatId))
	if err != nil {
		return fmt.Errorf("failed to find telegram chat: %w", err)
	}

	s.logger.Infof("telegram chat found: %s(%v)\n", s.telegramChat.Title, s.telegramChat.ID)

	s.telegramBot.Handle(tb.OnText, s.handleTelegramTextMessage)
	s.telegramBot.Handle(tb.OnPhoto, s.handleTelegramImageMessage)

	return nil
}

const TelegramToQQMessageHeaderFormat = "%s %s(%s) said:\n"

func makeTelegramToQQMessageHeader(m *tb.Message) string {
	return fmt.Sprintf(TelegramToQQMessageHeaderFormat,
		m.Sender.FirstName, m.Sender.LastName, m.Sender.Username)
}

func (s *Service) handleTelegramTextMessage(m *tb.Message) {

	s.logger.Infof("telegram message received: %v\n", m.ID)
	message := miraiMessage.NewSendingMessage()
	message.Append(miraiMessage.NewText(makeTelegramToQQMessageHeader(m) + m.Text))
	s.qqToSendMessageChannel <- &qqToSendMessage{
		originalTelegramMessageId: m.ID,
		toSend:                    message,
	}

}

func (s *Service) handleTelegramImageMessage(m *tb.Message) {
	s.logger.Infof("telegram message received: %v\n", m.ID)

	type imageElementOrError struct {
		imageElement *miraiMessage.GroupImageElement
		imageCaption string
		err          error
	}

	imageChan := make(chan imageElementOrError)

	imageDownloader := func() {
		reader, err := s.telegramBot.GetFile(m.Photo.MediaFile())
		if err != nil {
			imageChan <- imageElementOrError{
				err: fmt.Errorf("failed to download telegram photo: %w", err),
			}
		}

		data, err := ioutil.ReadAll(reader)
		if err != nil {
			imageChan <- imageElementOrError{
				err: fmt.Errorf("failed to download telegram photo: %w", err),
			}
		}

		readSeeker := bytes.NewReader(data)

		var groupImageElement *miraiMessage.GroupImageElement

		for i := 0; i < TryLimit; i++ {
			groupImageElement, err = s.qqClient.UploadGroupImage(s.config.QQ.GroupId, readSeeker)
			if err != nil {
				s.logger.Warningf("failed to upload qq group image: %v", err)
				continue
			}
			imageChan <- imageElementOrError{
				imageElement: groupImageElement,
				imageCaption: m.Photo.Caption,
			}
			return
		}

		if err != nil {
			imageChan <- imageElementOrError{
				err: fmt.Errorf("failed to upload qq group message: %w", err),
			}
		}
	}
	go imageDownloader()

	messageGenerator := func() (*miraiMessage.SendingMessage, error) {
		downloadResult := <-imageChan
		if downloadResult.err != nil {
			return nil, downloadResult.err
		}

		var message = miraiMessage.NewSendingMessage()
		message.Append(miraiMessage.NewText(makeTelegramToQQMessageHeader(m) + downloadResult.imageCaption))
		message.Append(downloadResult.imageElement)

		return message, nil
	}

	s.qqToSendMessageChannel <- &qqToSendMessage{
		originalTelegramMessageId: m.ID,
		toSend:                    messageGenerator,
	}
}

func (s *Service) loadQQDeviceInformation() {
	mirai.SystemDeviceInfo.Protocol = QQDeviceProtocol

	if isFileOrFolderExists(s.userDataPath(QQDeviceInformationFilename)) {
		if content, err := ioutil.ReadFile(s.userDataPath(QQDeviceInformationFilename)); err == nil {
			if mirai.SystemDeviceInfo.ReadJson(content) == nil {
				return
			}
		}
	}

	mirai.GenRandomDevice()
	err := ioutil.WriteFile(s.userDataPath(QQDeviceInformationFilename), mirai.SystemDeviceInfo.ToJson(), 0600)
	if err != nil {
		s.logger.Warningf("failed to presist device information: %v", err)
	}
	return
}

func (s *Service) loginQQAccountViaQR() error {
	s.qqClient = mirai.NewClientEmpty()
generateAndPresentQrCode:
	resp, err := s.qqClient.FetchQRCode()
	if err != nil {
		return fmt.Errorf("failed to fetch qr code: %w", err)
	}

	loginQr, err := qrcode.Decode(bytes.NewReader(resp.ImageData))
	preconditionWithMessage(err == nil, "failed to login qr code")

	fmt.Println()
	fmt.Println("Scan this qr code to login on mobile qq app:")
	//goland:noinspection GoNilness
	qrcodeTerminal.New().Get(loginQr.Content).Print()
	fmt.Println()

	var prevStatus mirai.QRCodeLoginState

	for {
		qrStatus, err := s.qqClient.QueryQRCodeStatus(resp.Sig)

		if err != nil {
			return fmt.Errorf("failed to query qr code ststus: %w", err)
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

	return nil
}

func (s *Service) loginQQAccountUsingPassword() error {
	s.qqClient = mirai.NewClient(s.config.QQ.Account, s.config.QQ.Password)

	loginResp, err := s.qqClient.Login()

	if err != nil {
		return fmt.Errorf("cannot login qq account: %w", err)
	}

	return s.handleQQLoginResponse(loginResp)
}

const QQSessionTokenFilename = "session.token"

func (s *Service) loginQQAccountUsingSessionToken() error {
	shouldRemoveCurrentSessionToken := true
	defer func() {
		if shouldRemoveCurrentSessionToken {
			_ = os.Remove(s.userDataPath(QQSessionTokenFilename))
		}
	}()

	if isFileOrFolderExists(s.userDataPath(QQSessionTokenFilename)) {
		s.logger.Info("session token file found, try login qq using session token")
		if sessionTokenData, err := ioutil.ReadFile(s.userDataPath(QQSessionTokenFilename)); err == nil {
			r := binary.NewReader(sessionTokenData)
			sessionTokenAccount := r.ReadInt64()
			if s.config.QQ.Account != 0 && sessionTokenAccount == s.config.QQ.Account {
				s.qqClient = mirai.NewClientEmpty()
				if err := s.qqClient.TokenLogin(sessionTokenData); err == nil {
					shouldRemoveCurrentSessionToken = false
					return nil
				} else {
					s.logger.Warningf("failed to login with session token: %v\n", err)
					return err
				}
			} else {
				return err
			}
		} else {
			return err
		}
	} else {
		return fmt.Errorf("session token does not exist")
	}
}

func (s *Service) setupQQClient() error {
	s.loadQQDeviceInformation()

	var qqLoginError error

	s.logger.Info("login qq account")

	qqLoginError = s.loginQQAccountUsingSessionToken()

	if qqLoginError == nil {
		goto loginSuccess
	}

	if s.config.QQ.LoginViaQrCode {
		qqLoginError = s.loginQQAccountViaQR()
	} else {
		qqLoginError = s.loginQQAccountUsingPassword()
	}

	if qqLoginError != nil {
		return fmt.Errorf("failed to login qq account: %w", qqLoginError)
	}

loginSuccess:
	s.logger.Infof("qq login success: %s(%v)\n", s.qqClient.Nickname, s.qqClient.Uin)

	s.qqClient.OnGroupMessage(s.handleQQGroupMessage)
	if s.config.Debug.QQDontFilterYourself {
		s.qqClient.OnSelfGroupMessage(s.handleQQGroupMessage)
	}
	s.qqClient.OnLog(s.handleQQLog)
	s.qqClient.OnGroupMessageRecalled(func(client *mirai.QQClient, event *mirai.GroupMessageRecalledEvent) {
		precondition(client == s.qqClient)

		if event.GroupCode != s.config.QQ.GroupId {
			return
		}

		s.logger.Debugf("qq message recalled: %v\n", event.MessageId)
	})

	if err := ioutil.WriteFile(s.userDataPath(QQSessionTokenFilename), s.qqClient.GenToken(), 0600); err != nil {
		s.logger.Warningf("failed to persist session token: %v", err)
	}

	return nil
}

func (s *Service) handleQQLog(client *mirai.QQClient, e *mirai.LogEvent) {
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

const QQToTelegramMessageHeaderFormat = "%s(%v) said:\n"

func makeQQToTelegramMessageHeader(message *miraiMessage.GroupMessage) string {
	return fmt.Sprintf(QQToTelegramMessageHeaderFormat, message.Sender.Nickname, message.Sender.Uin)
}

func (s *Service) handleQQGroupMessage(client *mirai.QQClient, message *miraiMessage.GroupMessage) {
	precondition(s.qqClient == client)
	s.logger.Infof("qq group message received: %v\n", message.Id)
	if message.GroupCode != s.config.QQ.GroupId ||
		(!s.config.Debug.QQDontFilterYourself && message.Sender.Uin == s.qqClient.Uin) {
		return
	}

	go s.composeAndSendTelegramMessage(message)
}

func (s *Service) qqFileToTelegramFile(element miraiMessage.IMessageElement) tb.File {
	var imageUrl string

	switch element.(type) {
	case *miraiMessage.ImageElement:
		imageElement := element.(*miraiMessage.ImageElement)
		imageUrl = imageElement.Url
	case *miraiMessage.GroupImageElement:
		imageElement := element.(*miraiMessage.GroupImageElement)
		imageUrl = imageElement.Url
	default:
		preconditionFailureWithMessage("not a fetchable element")
	}

	return tb.FromURL(imageUrl)
}

func (s *Service) composeAndSendTelegramMessage(message *miraiMessage.GroupMessage) {
	textMessage := makeQQToTelegramMessageHeader(message)
	album := tb.Album{}

	for _, element := range message.Elements {
		switch element.(type) {
		case *miraiMessage.TextElement:
			textMessage += element.(*miraiMessage.TextElement).Content
		}
	}

	for _, element := range message.Elements {
		switch element.(type) {
		case *miraiMessage.ImageElement, *miraiMessage.GroupImageElement:
			photo := &tb.Photo{File: s.qqFileToTelegramFile(element)}
			if textMessage != "" {
				photo.Caption = textMessage
			}
			textMessage = ""
			album = append(album, photo)
		}
	}

	var forwardedMessages []tb.Message
	var err error

	for i := 0; i < TryLimit; i++ {
		switch len(album) {
		case 0:
			message, innerErr := s.telegramBot.Send(s.telegramChat, textMessage)
			if err = innerErr; err != nil {
				goto handleError
			}
			//goland:noinspection GoNilness
			forwardedMessages = append(forwardedMessages, *message)
			break
		case 1:
			message, innerErr := s.telegramBot.Send(s.telegramChat, album[0])
			if err = innerErr; err != nil {
				goto handleError
			}
			//goland:noinspection GoNilness
			forwardedMessages = append(forwardedMessages, *message)
			break
		default:
			innerMessages, innerErr := s.telegramBot.SendAlbum(s.telegramChat, album)
			if err = innerErr; err != nil {
				goto handleError
			}
			forwardedMessages = append(forwardedMessages, innerMessages...)
			break
		}

	handleError:
		s.logger.Warningf("failed to forward message from qq: %v\n", err)
	}

	if err != nil {
		s.reportForwardFromQQToTelegramError(message, err)
		return
	}

	s.reportForwardFromQQToTelegram(message, forwardedMessages)
}

func (s *Service) reportForwardFromQQToTelegramError(message *miraiMessage.GroupMessage, err error) {
	s.logger.Errorf("failed to forward qq message(%v) to telegram: %v", message.Id, err)
}

func (s *Service) reportForwardFromQQToTelegram(message *miraiMessage.GroupMessage, forwarded []tb.Message) {
	var forwardedIds []int

	for _, message := range forwarded {
		forwardedIds = append(forwardedIds, message.ID)
	}

	s.logger.Infof("message forwarded: from qq(%v) to telegram(%v)", message.Id, forwardedIds)
}

func (s *Service) Stop() error {
	s.cancelFunc()

	s.workerWaitGroup.Wait()

	s.telegramBot.Stop()
	s.qqClient.Disconnect()

	s.logger.Infoln("service stopped")

	return nil
}

func (s *Service) Run() error {
	if !s.qqClient.Online {
		if err := s.setupQQClient(); err != nil {
			return s.reportIfError(err)
		}
	}

	s.workerWaitGroup.Add(1)
	go s.qqMessageSender()

	s.telegramBot.Start()

	s.logger.Infoln("service running")
	<-s.context.Done()
	return nil
}

var exitSignalList = []os.Signal{syscall.SIGKILL, syscall.SIGABRT, syscall.SIGINT, syscall.SIGTERM}

func (s *Service) handleSignals() {
	signalChannel := make(chan os.Signal)
	signal.Notify(signalChannel, exitSignalList...)

	go func() {
		for {
			select {
			case sig := <-signalChannel:
				s.logger.Infof("exit signal received: %v\n", sig)
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

	preconditionNoError(service.Run())
}
