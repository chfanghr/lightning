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
	"strconv"
	"strings"
	"sync"
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

	qqToSendMessageChannel       chan *qqToSendMessage
	telegramToSendMessageChannel chan *telegramToSendMessage

	workerWaitGroup sync.WaitGroup

	redisClient *redis.Client
}

type qqToSendMessage struct {
	originalTelegramMessageId int
	toSend                    interface{}
}

type telegramToSendMessage struct {
	originalQQMessageId int32
	toSend              interface{}
}

const MessageQueueSize = 100

func NewServiceFromConfig(config *Config) (*Service, error) {
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

	s.qqToSendMessageChannel = make(chan *qqToSendMessage, MessageQueueSize)
	s.telegramToSendMessageChannel = make(chan *telegramToSendMessage, MessageQueueSize)

	if err := s.setupRedisDatabase(); err != nil {
		s.redisClient = nil
		log.Warningf("failed to setup redis: %v", err)
	}

	return s, nil
}

const RedisVersionPrefix = "redis_version:"

const RedisUrlEnvKey = "REDIS_URL"

func (s *Service) setupRedisDatabase() (err error) {
	var options *redis.Options

	if s.config.Redis.Url == "" {
		if envRedisUrl := os.Getenv(RedisUrlEnvKey); envRedisUrl != "" {
			s.logger.Infof("using redis url from environment: %s", envRedisUrl)
			s.config.Redis.Url = envRedisUrl
		}
	}

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
	scanner := bufio.NewScanner(strings.NewReader(serverInfo.(string)))
	for scanner.Scan() {
		line := scanner.Text()
		if strings.HasPrefix(line, RedisVersionPrefix) {
			version := strings.TrimPrefix(line, RedisVersionPrefix)
			version = strings.TrimRight(version, "\r\n")
			log.Infof("redis server connected: %v", version)
			break
		}
	}

	return nil
}

func (s *Service) runQQMessageSender() {
	s.workerWaitGroup.Add(1)
	go s.qqMessageSender()
}

func (s *Service) runTelegramMessageSender() {
	s.workerWaitGroup.Add(1)
	go s.telegramMessageSender()
}

func (s *Service) qqMessageSender() {
	defer s.workerWaitGroup.Done()

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
					s.logger.Warningf("failed to generate qq message: %v", err)
				} else {
					break
				}
			}
		}

		if err != nil {
			err = fmt.Errorf("failed to generate qq message: %v", err)
		} else {
			for i := 0; i < TryLimit; i++ {
				groupMessage = s.qqClient.SendGroupMessage(s.config.QQ.GroupId, message)
				if groupMessage == nil || groupMessage.Id == -1 {
					s.logger.Warningln("failed to send qq group message")
					time.Sleep(time.Second)
				} else {
					break
				}
			}
		}

		s.reportForwardFromTelegramToQQ(toSend.originalTelegramMessageId, groupMessage, err)
	}

	for {
		select {
		case <-s.context.Done():
			for msg := range s.qqToSendMessageChannel {
				sendMessage(msg)
			}
			return
		case toSend := <-s.qqToSendMessageChannel:
			sendMessage(toSend)
		default:
			if err := s.ensureQQClientIsOnline(); err != nil {
				s.logger.Warningf("qq client is not online: %v", err)
			}
		}
	}
}

func (s *Service) reportForwardFromQQToTelegram(qqMessageId int32, forwarded interface{}, err error) {
	if err != nil {
		s.logger.Errorf("failed to forward qq message %v: %v", qqMessageId, err)
		return
	}

	var forwardedMessageIds []int
	switch forwarded.(type) {
	case *tb.Message:
		forwardedMessageIds = append(forwardedMessageIds, forwarded.(*tb.Message).ID)
	case []tb.Message:
		messages := forwarded.([]tb.Message)
		for _, message := range messages {
			forwardedMessageIds = append(forwardedMessageIds, message.ID)
		}
	}

	s.logger.Infof("qq message %v forwarded to telegram: %v", qqMessageId, forwardedMessageIds)
	s.recordForwardFromQQToTelegram(qqMessageId, forwardedMessageIds)
}

const QQMessageRecallExpireTime = time.Minute * 2

const QQToTelegramRedisRecordKeyFormat = "qq2tg:%d"

func (s *Service) recordForwardFromQQToTelegram(qqMessageId int32, forwardedTelegramMessageIds []int) {
	if s.redisClient == nil {
		return
	}
	recordKey := fmt.Sprintf(QQToTelegramRedisRecordKeyFormat, qqMessageId)
	pipeline := s.redisClient.Pipeline()
	for _, id := range forwardedTelegramMessageIds {
		pipeline.RPush(s.redisClient.Context(), recordKey, id)
	}
	pipeline.Expire(s.redisClient.Context(), recordKey, QQMessageRecallExpireTime)
	go s.executeRedisPipeline(pipeline, func() {
		s.logger.Infof("qq message %v recorded", qqMessageId)
	})
}

func (s *Service) executeRedisPipeline(pipeline redis.Pipeliner, onSuccess func()) {
	_, err := pipeline.Exec(s.redisClient.Context())
	if err != nil {
		s.logger.Warningf("failed to execute redis pipeline: %v", err)
	}
	onSuccess()
}

func (s *Service) telegramMessageSender() {
	defer s.workerWaitGroup.Done()

	sendMessage := func(toSend *telegramToSendMessage) {
		var res interface{}
		var err error

		for i := 0; i < TryLimit; i++ {
			switch toSend.toSend.(type) {
			case tb.Album:
				res, err = s.telegramBot.SendAlbum(s.telegramChat, toSend.toSend.(tb.Album))
			default:
				res, err = s.telegramBot.Send(s.telegramChat, toSend.toSend)
			}

			if err == nil {
				break
			}
		}

		s.reportForwardFromQQToTelegram(toSend.originalQQMessageId, res, err)
	}

	for {
		select {
		case <-s.context.Done():
			for toSend := range s.telegramToSendMessageChannel {
				sendMessage(toSend)
			}
			return
		case toSend := <-s.telegramToSendMessageChannel:
			sendMessage(toSend)
		}
	}
}

func (s *Service) reportForwardFromTelegramToQQ(telegramMessageId int, qqGroupMessage *miraiMessage.GroupMessage, err error) {
	if err != nil {
		s.logger.Errorf("failed to forward telegram message %v: %v", telegramMessageId, err)
		return
	}
	s.logger.Infof("telegram message %v forwarded to qq: %v", telegramMessageId, qqGroupMessage.Id)
	s.recordForwardFromTelegramToQQ(telegramMessageId, qqGroupMessage.Id, qqGroupMessage.InternalId)
}

const TelegramToQQRedisRecordKeyFormat = "tg2qq:%d"

func (s *Service) recordForwardFromTelegramToQQ(telegramMessageId int, qqMessageId int32, qqMessageInternalId int32) {
	if s.redisClient == nil {
		return
	}
	recordKey := fmt.Sprintf(TelegramToQQRedisRecordKeyFormat, telegramMessageId)
	pipeline := s.redisClient.Pipeline()
	pipeline.RPush(s.redisClient.Context(), recordKey, qqMessageId, qqMessageInternalId)
	pipeline.Expire(s.redisClient.Context(), recordKey, QQMessageRecallExpireTime)

	go s.executeRedisPipeline(pipeline, func() {
		s.logger.Infof("telegram message %v recorded", telegramMessageId)
	})
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

const TelegramRecallMessageCommand = "/recall"

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
		if !update.Message.Sender.IsBot &&
			update.Message.Chat.ID == s.config.Telegram.ChatId {
			s.logger.Infof("telegram message received: %v", update.Message.ID)
			return true
		}
		return false
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

	s.logger.Infof("telegram chat found: %s(%v)", s.telegramChat.Title, s.telegramChat.ID)

	s.telegramBot.Handle(tb.OnText, s.handleTelegramTextMessage)
	s.telegramBot.Handle(tb.OnPhoto, s.handleTelegramImageMessage)
	s.telegramBot.Handle(TelegramRecallMessageCommand, s.handleTelegramRecallCommand)

	return nil
}

func (s *Service) handleTelegramRecallCommand(m *tb.Message) {
	cleanUp := func() {
		err := s.telegramBot.Delete(telegramToRecallMessage{
			messageID: strconv.Itoa(m.ID),
			chatID:    s.telegramChat.ID,
		})
		if err != nil {
			s.logger.Warningf("failed to clean up telegram recall command message %v: %v", m.ID, err)
		}
	}

	if m.ReplyTo == nil {
		cleanUp()
		return
	}

	toRecallMessageId := m.ReplyTo.ID
	s.logger.Infof("recall command invoked: %v", toRecallMessageId)

	recallTask := func() {
		defer cleanUp()

		recordKey := fmt.Sprintf(TelegramToQQRedisRecordKeyFormat, toRecallMessageId)
		res, err := s.redisClient.LRange(s.redisClient.Context(), recordKey, 0, -1).Result()
		if err != nil {
			s.logger.Warningf("failed to find telegram message %v to qq message record: %v", m.ReplyTo.ID, err)
			return
		}
		qqMessageId, err := strconv.ParseInt(res[0], 10, 32)
		preconditionNoError(err)
		qqMessageInternalId, err := strconv.ParseInt(res[1], 10, 32)
		preconditionNoError(err)

		if err := s.qqClient.RecallGroupMessage(s.config.QQ.GroupId, int32(qqMessageId), int32(qqMessageInternalId)); err != nil {
			s.logger.Warningf("failed to recall telegram message %v from qq: %v", m.ReplyTo.ID, err)
			return
		}

		if err := s.telegramBot.Delete(telegramToRecallMessage{
			messageID: strconv.Itoa(m.ReplyTo.ID),
			chatID:    s.telegramChat.ID,
		}); err != nil {
			s.logger.Warningf("failed to delete original telegram message %v: %v", m.ReplyTo.ID, err)
		}
	}

	go recallTask()
}

const TelegramToQQMessageHeaderFormat = "%s %s(%s) said:\n"

func makeTelegramToQQMessageHeader(m *tb.Message) string {
	return fmt.Sprintf(TelegramToQQMessageHeaderFormat,
		m.Sender.FirstName, m.Sender.LastName, m.Sender.Username)
}

func (s *Service) handleTelegramTextMessage(m *tb.Message) {
	message := miraiMessage.NewSendingMessage()
	message.Append(miraiMessage.NewText(makeTelegramToQQMessageHeader(m) + m.Text))
	s.qqToSendMessageChannel <- &qqToSendMessage{
		originalTelegramMessageId: m.ID,
		toSend:                    message,
	}
}

func (s *Service) handleTelegramImageMessage(m *tb.Message) {
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
				imageCaption: m.Caption,
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
			fmt.Printf("sms code has been sent to: %v", loginResp.SMSPhone)
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
		s.logger.Info("qq session token file found")
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
	s.logger.Infof("qq login success: %s(%v)", s.qqClient.Nickname, s.qqClient.Uin)

	s.qqClient.OnGroupMessage(s.handleQQGroupMessage)
	if s.config.Debug.QQDontFilterYourself {
		s.qqClient.OnSelfGroupMessage(s.handleQQGroupMessage)
	}
	s.qqClient.OnLog(s.handleQQLog)
	s.qqClient.OnGroupMessageRecalled(s.handleQQGroupMessageRecalled)

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

	s.logger.Logf(logLevel, "qq client: %v", e.Message)
}

const QQToTelegramMessageHeaderFormat = "%s(%v) said:\n"

func makeQQToTelegramMessageHeader(message *miraiMessage.GroupMessage) string {
	return fmt.Sprintf(QQToTelegramMessageHeaderFormat, message.Sender.Nickname, message.Sender.Uin)
}

type telegramToRecallMessage struct {
	messageID string
	chatID    int64
}

func (t telegramToRecallMessage) MessageSig() (messageID string, chatID int64) {
	return t.messageID, t.chatID
}

func (s *Service) handleQQGroupMessageRecalled(client *mirai.QQClient, event *mirai.GroupMessageRecalledEvent) {
	precondition(client == s.qqClient)
	if event.GroupCode != s.config.QQ.GroupId {
		return
	}
	s.logger.Debugf("qq message recalled: %v\n", event.MessageId)

	if s.redisClient == nil {
		return
	}

	recallTask := func() {
		messageId := event.MessageId
		recordKey := fmt.Sprintf(QQToTelegramRedisRecordKeyFormat, messageId)

		result, err := s.redisClient.LRange(s.redisClient.Context(), recordKey, 0, -1).Result()
		if err != nil {
			s.logger.Warningf("cannot recall qq message %v from telegram: %v", messageId, err)
		}

		for _, telegramMessageId := range result {
			err := s.telegramBot.Delete(telegramToRecallMessage{
				messageID: telegramMessageId,
				chatID:    s.telegramChat.ID,
			})
			if err != nil {
				log.Warningf("cannot recall qq message %v from telegram", err)
			} else {
				log.Infof("recalled qq message %v from telegram: %v", messageId, telegramMessageId)
			}
		}

		s.redisClient.Del(s.redisClient.Context(), recordKey)
	}

	go recallTask()
}

func (s *Service) handleQQGroupMessage(client *mirai.QQClient, message *miraiMessage.GroupMessage) {
	precondition(s.qqClient == client)
	if message.GroupCode != s.config.QQ.GroupId ||
		(!s.config.Debug.QQDontFilterYourself && message.Sender.Uin == s.qqClient.Uin) {
		return
	}
	s.logger.Infof("qq group message received: %v", message.Id)

	s.composeAndSendTelegramMessage(message)
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

	toSend := &telegramToSendMessage{originalQQMessageId: message.Id}

	switch len(album) {
	case 0:
		toSend.toSend = textMessage
	case 1:
		toSend.toSend = album[0]
	default:
		toSend.toSend = album
	}

	s.telegramToSendMessageChannel <- toSend
}

func (s *Service) Stop() {
	s.cancelFunc()

	s.workerWaitGroup.Wait()

	s.telegramBot.Stop()
	s.qqClient.Disconnect()

	if s.redisClient != nil {
		if err := s.redisClient.Close(); err != nil {
			s.logger.Warningf("failed to colse redis client: %v", err)
		}
	}

	s.logger.Infoln("service stopped")
}

func (s *Service) ensureQQClientIsOnline() error {
	if !s.qqClient.Online {
		if err := s.setupQQClient(); err != nil {
			return s.reportIfError(err)
		}
	}
	return nil
}

func (s *Service) Run(handleSignals bool) error {
	if err := s.ensureQQClientIsOnline(); err != nil {
		return err
	}

	s.runQQMessageSender()
	s.runTelegramMessageSender()

	s.telegramBot.Start()

	s.logger.Infoln("service running")
	if handleSignals {
		s.handleSignals()
	}
	<-s.context.Done()
	return nil
}

func (s *Service) handleSignals() {
	signalChannel := make(chan os.Signal)
	signal.Notify(signalChannel, os.Interrupt, os.Kill)

	for {
		select {
		case sig := <-signalChannel:
			s.logger.Infof("exit signal received: %v", sig)
			s.Stop()
			return
		case <-s.context.Done():
			return
		}
	}
}

var configFilename = flag.String("c", "config.json", "configuration file to be used")

func main() {
	flag.Parse()

	config, err := NewConfigFromFile(*configFilename)
	preconditionNoError(err)

	service, err := NewServiceFromConfig(config)
	preconditionNoError(err)

	preconditionNoError(service.Run(true))
}
