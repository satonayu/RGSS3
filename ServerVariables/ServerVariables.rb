#******************************************************************************
#    RGSS3 - サーバー変数
#      Created by 睡工房 (http://hime.be/)
#        License: くいなちゃんライセンス( http://kuina.ch/others/license )
#******************************************************************************
=begin
  ◆機能
    ゲーム変数をサーバーに保存し、プレイヤー全体での変数として管理できます。

  ◆使い方
    書式のみ記載。細かな説明は配布元をご確認ください。
    https://github.com/satonayu/RGSS3/tree/master/ServerVariables

  ・サーバー変数の取得
    書式：GET id id id id...

  ・サーバー変数の更新
    書式：UPDATE id id id id...

  ・サーバー変数の足し算
    書式：ADD id id id id...

  ・サーバー変数とゲーム変数の大きい方を記録
    書式：MAX id id id id...

  ・サーバー変数とゲーム変数の小さい方を記録
    書式：MIN id id id id...

  ・ランキングサーバー（大きい順）
    書式：MAXRANK sid-eid nid

  ・ランキングサーバー（小さい順）
    書式：MINRANK sid-eid nid
=end

module SV
  # サーバーでゲーム変数を保存する時に使用するグループ名です。
  # この名前が同じ値の場合、別のゲームからでもサーバー変数が書き換えられます。
  # 他のゲームと被らないよう、ランダムで長い名前を付けてください。
  # ※検索で「ランダム文字列 生成」で検索したサイトで作成すると便利です。
  # ※32～255文字、使用可能文字…半角英数字と半角ハイフン、半角アンダーバー
  # 例)BgbCRWQrB4dwQ4eN5Z4HpjVXSgdjcbVPz32JmNFiWup3PUeJLbAYzHTdwQAfZFAG
  KEYCODE = "BgbCRWQrB4dwQ4eN5Z4HpjVXSgdjcbVPz32JmNFiWup3PUeJLbAYzHTdwQAfZFAG"

  # 処理の成功/失敗を判断するためのゲームスイッチID
  # 処理が成功した場合はON、失敗した場合はOFFになります。
  # イベントの条件分岐に使用してください。
  RESULT_SW = 10
end



module SV
  #--------------------------------------------------------------------------
  # ■ サーバー変数を取得
  #--------------------------------------------------------------------------
  def self.get(param)
    $game_switches[RESULT_SW] = false
    begin
      if param.strip !~ /\A\d+(\s+\d+)*\z/
        raise SVError, "Error: ParameterFormat: #{param}"
      end
      
      indexes = param.strip.split(/\s+/)
      parameters = SVParameters.new("GET", KEYCODE)
      parameters["Indexes"]   = HttpClient.url_encode(indexes.join(ID_SEP))
      parameters["Signature"] = SV.sign(parameters, GET_URL)
      
      result = SV.access(GET_URL, CONTENT_TYPE, "", parameters.to_s)
      SV.update_game_variables(result)
      $game_switches[RESULT_SW] = true
      
    rescue SVError, NetError => err
      Log.error(err)
      
    ensure
      parameters.clear unless parameters.nil?
    end
  end
  #--------------------------------------------------------------------------
  # ■ サーバー変数を更新
  #--------------------------------------------------------------------------
  def self.update(param)
    $game_switches[RESULT_SW] = false
    begin
      if param.strip !~ /\A\d+(\s+\d+)*\z/
        raise SVError, "Error: ParameterFormat: #{param}"
      end
      
      indexes = param.strip.split(/\s+/)
      values  = indexes.map {|key| $game_variables[key.to_i]}
      parameters = SVParameters.new("UPDATE", KEYCODE)
      parameters["Indexes"]   = HttpClient.url_encode(indexes.join(ID_SEP))
      parameters["Values"]    = HttpClient.url_encode(values.join(ID_SEP))
      parameters["Signature"] = SV.sign(parameters, UPDATE_URL)
      
      SV.access(UPDATE_URL, CONTENT_TYPE, "", parameters.to_s)
      $game_switches[RESULT_SW] = true
      
    rescue SVError, NetError => err
      Log.error(err)
      
    ensure
      parameters.clear unless parameters.nil?
    end
  end
  #--------------------------------------------------------------------------
  # ■ サーバー変数に足し算
  #--------------------------------------------------------------------------
  def self.add(param)
    $game_switches[RESULT_SW] = false
    begin
      if param.strip !~ /\A\d+(\s+\d+)*\z/
        raise SVError, "Error: ParameterFormat: #{param}"
      end
      
      indexes = param.strip.split(/\s+/)
      values  = indexes.map {|key| $game_variables[key.to_i]}
      parameters = SVParameters.new("ADD", KEYCODE)
      parameters["Indexes"]   = HttpClient.url_encode(indexes.join(ID_SEP))
      parameters["Values"]    = HttpClient.url_encode(values.join(ID_SEP))
      parameters["Signature"] = SV.sign(parameters, ADD_URL)
      
      result = SV.access(ADD_URL, CONTENT_TYPE, "", parameters.to_s)
      SV.update_game_variables(result)
      $game_switches[RESULT_SW] = true
      
    rescue SVError, NetError => err
      Log.error(err)
      
    ensure
      parameters.clear unless parameters.nil?
    end
  end
  #--------------------------------------------------------------------------
  # ■ サーバー変数とゲーム変数を比較して大きい側を記録
  #--------------------------------------------------------------------------
  def self.max(param)
    $game_switches[RESULT_SW] = false
    begin
      if param.strip !~ /\A\d+(\s+\d+)*\z/
        raise SVError, "Error: ParameterFormat: #{param}"
      end
      
      indexes = param.strip.split(/\s+/)
      values  = indexes.map {|key| $game_variables[key.to_i]}
      parameters = SVParameters.new("MAX", KEYCODE)
      parameters["Indexes"]   = HttpClient.url_encode(indexes.join(ID_SEP))
      parameters["Values"]    = HttpClient.url_encode(values.join(ID_SEP))
      parameters["Signature"] = SV.sign(parameters, MAX_URL)
      
      result = SV.access(MAX_URL, CONTENT_TYPE, "", parameters.to_s)
      SV.update_game_variables(result)
      $game_switches[RESULT_SW] = true
      
    rescue SVError, NetError => err
      Log.error(err)
      
    ensure
      parameters.clear unless parameters.nil?
    end
  end
  #--------------------------------------------------------------------------
  # ■ サーバー変数とゲーム変数を比較して小さい側を記録
  #--------------------------------------------------------------------------
  def self.min(param)
    begin
      if param.strip !~ /\A\d+(\s+\d+)*\z/
        raise SVError, "Error: ParameterFormat: #{param}"
      end
      
      indexes = param.strip.split(/\s+/)
      values  = indexes.map {|key| $game_variables[key.to_i]}
      parameters = SVParameters.new("MIN", KEYCODE)
      parameters["Indexes"]   = HttpClient.url_encode(indexes.join(ID_SEP))
      parameters["Values"]    = HttpClient.url_encode(values.join(ID_SEP))
      parameters["Signature"] = SV.sign(parameters, MIN_URL)
      
      result = SV.access(MIN_URL, CONTENT_TYPE, "", parameters.to_s)
      SV.update_game_variables(result)
      $game_switches[RESULT_SW] = true
      
    rescue SVError, NetError => err
      Log.error(err)
      
    ensure
      parameters.clear unless parameters.nil?
    end
  end
  #--------------------------------------------------------------------------
  # ■ ランキングサーバー（大きい順）
  #--------------------------------------------------------------------------
  def self.maxrank(param)
    begin
      if param.strip !~ /\A(\d+)\-(\d+)\s+(\d+)\z/
        raise SVError, "Error: ParameterFormat: #{param}"
      end
      
      indexes = [*($1.to_i..$2.to_i)]
      score  = $game_variables[$3.to_i].to_s
      parameters = SVParameters.new("MAXRANK", KEYCODE)
      parameters["Indexes"]   = HttpClient.url_encode(indexes.join(ID_SEP))
      parameters["Score"]     = HttpClient.url_encode(score)
      parameters["Signature"] = SV.sign(parameters, MAXRANK_URL)
      
      result = SV.access(MAXRANK_URL, CONTENT_TYPE, "", parameters.to_s)
      SV.update_game_variables(result)
      $game_switches[RESULT_SW] = true
      
    rescue SVError, NetError => err
      Log.error(err)
      
    ensure
      parameters.clear unless parameters.nil?
    end
  end
  #--------------------------------------------------------------------------
  # ■ ランキングサーバー（小さい順）
  #--------------------------------------------------------------------------
  def self.minrank(param)
    begin
      if param.strip !~ /\A(\d+)\-(\d+)\s+(\d+)\z/
        raise SVError, "Error: ParameterFormat: #{param}"
      end
      
      indexes = [*($1.to_i..$2.to_i)]
      score  = $game_variables[$3.to_i].to_s
      parameters = SVParameters.new("MINRANK", KEYCODE)
      parameters["Indexes"]   = HttpClient.url_encode(indexes.join(ID_SEP))
      parameters["Score"]     = HttpClient.url_encode(score)
      parameters["Signature"] = SV.sign(parameters, MINRANK_URL)
      
      result = SV.access(MINRANK_URL, CONTENT_TYPE, "", parameters.to_s)
      SV.update_game_variables(result)
      $game_switches[RESULT_SW] = true
      
    rescue SVError, NetError => err
      Log.error(err)
      
    ensure
      parameters.clear unless parameters.nil?
    end
  end
  #--------------------------------------------------------------------------
  # ■ サーバーにアクセス
  #--------------------------------------------------------------------------
  def self.access(url, content_type, body, add)
    begin
      client = HttpClient.new
      client.access(url, content_type, body, add)
      if client.status != 200
        raise SVError, "Error: StatusCode: #{client.status}"
      end
      if client.data =~ /\Aerror:(.+)\z/
        raise SVError, "Error: #{$1}"
      end
      if client.data !~ /\Asuccess:(.+)\z/
        raise SVError, "Error: UndefinedError"
      end
      return $1
    ensure
      client.dispose unless client.nil?
    end
  end
  #--------------------------------------------------------------------------
  # ■ ゲーム変数を更新
  #--------------------------------------------------------------------------
  def self.update_game_variables(text)
    text.split(ID_SEP).each do |item|
      if item =~ /\A(\d+)&=&([+-]?\d+(?:\.\d+)?)\z/
        $game_variables[$1.to_i] = $2.to_i
      end
    end
  end
  #--------------------------------------------------------------------------
  # ■ 署名を作成
  #--------------------------------------------------------------------------
  def self.sign(parameters, url)
    key   = HttpClient.url_encode(parameters["Keycode"])
    data  = HttpClient.url_encode(parameters["Method"])
    data += "&" + HttpClient.url_encode(url)
    data += "&" + HttpClient.url_encode(parameters.to_sign)
    sign  = Digest.hmac_sha1(key, data)
    return  HttpClient.url_encode(HttpClient.base64_encode(sign))
  end
  #--------------------------------------------------------------------------
  # ■ 定数
  #--------------------------------------------------------------------------
  CONTENT_TYPE = "Content-Type: application/x-www-form-urlencoded"
  ID_SEP    = "&,&"
  PARAM_SEP = "&=&"
  GET_URL     = "https://api.hime.be/variables/get/"
  UPDATE_URL  = "https://api.hime.be/variables/update/"
  ADD_URL     = "https://api.hime.be/variables/add/"
  MAX_URL     = "https://api.hime.be/variables/max/"
  MIN_URL     = "https://api.hime.be/variables/min/"
  MAXRANK_URL = "https://api.hime.be/variables/maxrank/"
  MINRANK_URL = "https://api.hime.be/variables/minrank/"
end



class SVParameters
  #--------------------------------------------------------------------------
  # ■ オブジェクト初期化
  #--------------------------------------------------------------------------
  def initialize(method, keycode)
    if keycode !~ /\A[a-zA-Z0-9]{32,255}\z/
      raise SVError, "Error: KeycodeFormat"
    end
    @parameters = Hash.new("")
    @parameters["Method"]  = method
    @parameters["Keycode"] = keycode
    @parameters["Timestamp"] = Time.now.to_i
    @parameters["Keystate"]  = SVParameters.random_string(64)
  end
  #--------------------------------------------------------------------------
  # ■ パラメータの設定
  #--------------------------------------------------------------------------
  def []=(key, value)
    @parameters[key] = value
  end
  #--------------------------------------------------------------------------
  # ■ パラメータの取得
  #--------------------------------------------------------------------------
  def [](key)
    @parameters[key]
  end
  #--------------------------------------------------------------------------
  # ■ パラメーターの消去
  #--------------------------------------------------------------------------
  def clear
    @parameters.clear
  end
  #--------------------------------------------------------------------------
  # ■ 文字列へ変換
  #--------------------------------------------------------------------------
  def to_s
    @parameters.map {|k, v| "#{k}: #{v}"}.join("\n")
  end
  #--------------------------------------------------------------------------
  # ■ 署名用文字列へ変換
  #--------------------------------------------------------------------------
  def to_sign
    keys = ["Method", "Keycode", "Timestamp", "Keystate", "Indexes"]
    keys.map {|key| "#{key}: #{@parameters[key]}"}.join(",")
  end
  #--------------------------------------------------------------------------
  # ■ 任意の文字数のランダムな文字列を作成して返す
  #--------------------------------------------------------------------------
  def self.random_string(num)
    o = [('a'..'z'), ('A'..'Z'), ('0'..'9')].map { |i| i.to_a }.flatten
    (0...num).map { o[rand(o.size)] }.join
  end
end



module Digest
  #--------------------------------------------------------------------------
  # ■ 16進ダイジェスト値生成（HMAC-SHA1）
  #--------------------------------------------------------------------------
  def self.hmac_sha1(key, param)
    key = digest(key) if key.size > 64
    ikey = ("\x36" * 64).unpack("C*")
    okey = ("\x5c" * 64).unpack("C*")
    key.unpack("C*").each_with_index do |uchar, i|
      ikey[i] ^= uchar
      okey[i] ^= uchar
    end
    value = digest(ikey.pack("C*") + param)
    value = digest(okey.pack("C*") + value)
    return value
  end
  #--------------------------------------------------------------------------
  # ■ SHA-1 ダイジェストを計算
  #--------------------------------------------------------------------------
  def self.digest(data)
    h0 = 0x67452301
    h1 = 0xEFCDAB89
    h2 = 0x98BADCFE
    h3 = 0x10325476
    h4 = 0xC3D2E1F0

    # メッセージ拡張（64の倍数）
    msg = message_extension(data)

    # ダイジェストの計算
    (msg.size / 64).times do |i|
      
      # メッセージ分割
      w = msg[i * 64, 64].unpack("N*")
      
      # 計算その１
      (16...80).each do |t|
        w[t] = circular_shift_left(w[t - 3] ^ w[t - 8] ^ w[t - 14] ^ w[t - 16], 1)
      end

      # 初期化
      a = h0
      b = h1
      c = h2
      d = h3
      e = h4

      # 計算その２（定義関数使用）
      80.times do |t|
        temp = 0xffffffff & (circular_shift_left(a, 5) + f(t, b, c, d) + e + w[t] + k(t))
        e = d
        d = c
        c = circular_shift_left(b, 30)
        b = a
        a = temp
      end

      # 初期値に加算
      h0 = 0xffffffff & (h0 + a)
      h1 = 0xffffffff & (h1 + b)
      h2 = 0xffffffff & (h2 + c)
      h3 = 0xffffffff & (h3 + d)
      h4 = 0xffffffff & (h4 + e)
    end

    return [sprintf("%08X%08X%08X%08X%08X", h0, h1, h2, h3, h4)].pack("H*")
  end
  #--------------------------------------------------------------------------
  # ■ bit を左にローテート
  #--------------------------------------------------------------------------
  def self.circular_shift_left(target, size)
    (0xffffffff & (target << size)) | (target >> (32 - size))
  end
  #--------------------------------------------------------------------------
  # ■ メッセージを拡張
  #--------------------------------------------------------------------------
  def self.message_extension(message)
    ret = message + ["100000000"].pack("B*")
    ret += ([0] * ((56 - ret.size % 64) % 64)).pack("C*")
    ret += [sprintf("%016X", message.size * 8)].pack("H*")
    return ret
  end
  #--------------------------------------------------------------------------
  # ■ 定義関数
  #--------------------------------------------------------------------------
  def self.f(i, b, c, d)
    return (b & c) | (~b & d)           if i < 20
    return (b ^ c ^ d)                  if i < 40
    return (b & c) | (b & d) | (c & d)  if i < 60
    return b ^ c ^ d
  end
  #--------------------------------------------------------------------------
  # ■ 定数
  #--------------------------------------------------------------------------
  def self.k(i)
    return 0x5A827999 if i < 20
    return 0x6ED9EBA1 if i < 40
    return 0x8F1BBCDC if i < 60
    return 0xCA62C1D6
  end
end



class SVError               < StandardError;  end
class NetError              < StandardError;  end
class NetConnectionError    < NetError;       end
class NetOpenError          < NetError;       end
class NetServerConnectError < NetError;       end
class NetOpenRequestError   < NetError;       end
class NetAddRequestError    < NetError;       end
class NetSendRequestError   < NetError;       end
class NetQueryInfoError     < NetError;       end
class NetReadingError       < NetError;       end



class HttpClient
  #--------------------------------------------------------------------------
  # ■ 定数
  #--------------------------------------------------------------------------
  AGENT_NAME = "ServerVariableByRgss3"
  HTTP_PORT  = 80
  HTTPS_PORT = 443
  SERVICE_HTTP = 3
  VERSION = "HTTP/1.1"

  INTERNET_FLAG_KEEP_CONNECTION          = 0x00400000
  INTERNET_FLAG_NO_CACHE_WRITE           = 0x04000000
  INTERNET_FLAG_NO_AUTH                  = 0x00040000
  INTERNET_FLAG_RELOAD                   = 0x80000000
  INTERNET_FLAG_SECURE                   = 0x00800000
  INTERNET_FLAG_IGNORE_CERT_CN_INVALID   = 0x00001000
  INTERNET_FLAG_IGNORE_CERT_DATE_INVALID = 0x00002000

  #--------------------------------------------------------------------------
  # ■ Win32API
  #--------------------------------------------------------------------------
  INTERNET_CONNECTION      = Win32API.new("wininet", "InternetAttemptConnect", "i", "i")
  INTERNET_OPEN            = Win32API.new("wininet", "InternetOpen", "plppl", "l")
  INTERNET_OPTION_SET      = Win32API.new("wininet", "InternetSetOption", "llpl", "i")
  INTERNET_CONNECT         = Win32API.new("wininet", "InternetConnect", "lpipplll", "l")
  INTERNET_CLOSE           = Win32API.new("wininet", "InternetCloseHandle", "l", "i")
  HTTP_OPEN_REQUEST        = Win32API.new("wininet", "HttpOpenRequest", "lpppplll", "l")
  HTTP_SEND_REQUEST        = Win32API.new("wininet", "HttpSendRequest", "lplpl", "l")
  HTTP_ADD_REQUEST_HEADERS = Win32API.new("wininet", "HttpAddRequestHeaders", "lpll", "i")
  HTTP_READING             = Win32API.new("wininet", "InternetReadFile", "lpip", "i")
  HTTP_QUERY               = Win32API.new("wininet", "HttpQueryInfo", "llppl", "i")

  #--------------------------------------------------------------------------
  # ■ 公開インスタンス変数
  #--------------------------------------------------------------------------
  attr_reader   :status         # ステータスコード
  attr_reader   :data           # 取得データ
  attr_accessor :method         # 
  
  #--------------------------------------------------------------------------
  # ■ オブジェクト初期化
  #--------------------------------------------------------------------------
  def initialize
    @server = ""
    @path   = ""
    @method = "POST"
    @secure = false
    @h_net  = 0
    @h_http = 0
    @h_request = 0
    @status = ""
    @data   = ""
  end
  #--------------------------------------------------------------------------
  # ■ 解放
  #--------------------------------------------------------------------------
  def dispose
  end
  #--------------------------------------------------------------------------
  # ■ サーバーにアクセスし、レスポンスを取得
  #--------------------------------------------------------------------------
  def access(url, header, body, add_headers = "")
    begin
      url_crack(url)
      call_net_connection
      call_net_open
      call_setting_options
      call_server_connect
      call_open_request
      call_add_request_headers(add_headers)
      call_send_request(header, body)
      call_query_info_status_code
      call_http_reading

    rescue NetError => err
      Log.error(err)

    ensure
      call_net_close
    end
  end
  #--------------------------------------------------------------------------
  # ■ ネットに接続できる状態か確認
  #--------------------------------------------------------------------------
  def call_net_connection
    ret = INTERNET_CONNECTION.call(0)
    raise NetConnectionError if ret != 0
  end
  #--------------------------------------------------------------------------
  # ■ ネット接続のための初期化を実施
  #--------------------------------------------------------------------------
  def call_net_open
    @h_net = INTERNET_OPEN.call(AGENT_NAME, 0, nil, nil, 0)
    raise NetOpenError if @h_net == 0
  end
  #--------------------------------------------------------------------------
  # ■ ネット接続に関する設定を実施
  #--------------------------------------------------------------------------
  def call_setting_options
    option1 = 0x00000002      # 接続時のタイムアウト設定を要求
    option2 = 0x00000006      # データ取得時のタイムアウト設定を要求
    timeout = "2000"          # タイムアウトを設定
    INTERNET_OPTION_SET.call(@h_net, option1, timeout, timeout.size)
    INTERNET_OPTION_SET.call(@h_net, option2, timeout, timeout.size)
  end
  #--------------------------------------------------------------------------
  # ■ サーバーに接続
  #--------------------------------------------------------------------------
  def call_server_connect
    port = @secure ? HTTPS_PORT : HTTP_PORT
    @h_http = INTERNET_CONNECT.call(@h_net, @server, port, "", "", SERVICE_HTTP, 0, 0)
    raise NetServerConnectError if @h_http == 0
  end
  #--------------------------------------------------------------------------
  # ■ HTTPリクエストを開く
  #--------------------------------------------------------------------------
  def call_open_request
    flag  = INTERNET_FLAG_KEEP_CONNECTION
    flag |= INTERNET_FLAG_NO_CACHE_WRITE
    flag |= INTERNET_FLAG_NO_AUTH
    flag |= INTERNET_FLAG_RELOAD
    if @secure
      flag |= INTERNET_FLAG_SECURE
      flag |= INTERNET_FLAG_IGNORE_CERT_CN_INVALID
      flag |= INTERNET_FLAG_IGNORE_CERT_DATE_INVALID
    end
    @h_request = HTTP_OPEN_REQUEST.call(@h_http, @method, @path, VERSION, nil, 0, flag, 0)
    raise NetOpenRequestError if @h_request == 0
  end
  #--------------------------------------------------------------------------
  # ■ HTTPのヘッダーを追加
  #--------------------------------------------------------------------------
  def call_add_request_headers(add_headers)
    return if add_headers.size == 0
    ret = HTTP_ADD_REQUEST_HEADERS.call(@h_request, add_headers, add_headers.size, 0x20000000 | 0x80000000)
    raise NetAddRequestError if ret == 0
  end
  #--------------------------------------------------------------------------
  # ■ HTTPのリクエストを送信
  #--------------------------------------------------------------------------
  def call_send_request(header, body)
    ret = HTTP_SEND_REQUEST.call(@h_request, header, header.size, body, body.size)
    raise NetSendRequestError if ret == 0
  end
  #--------------------------------------------------------------------------
  # ■ サーバーから返されたステータスコード取得
  #--------------------------------------------------------------------------
  def call_query_info_status_code
    buffer    = " " * 16
    read_size = " " * 16
    ret = HTTP_QUERY.call(@h_request, 0x00000013, buffer, read_size, 0)
    raise NetQueryInfoError if ret == 0
    @status = buffer[0, read_size.unpack("L!")[0]].to_i
  end
  #--------------------------------------------------------------------------
  # ■ サーバーから返されたリソースのサイズ取得
  #--------------------------------------------------------------------------
  def call_query_info_size
    buffer    = " " * 16
    read_size = " " * 16
    ret = HTTP_QUERY.call(@h_request, 0x00000005, buffer, read_size, 0)
    size = buffer[0, read_size.unpack("L!")[0]]
    return size.to_i if size =~ /^\d+$/
    return 65535
  end
  #--------------------------------------------------------------------------
  # ■ HTTPのレスポンスを読み取る
  #--------------------------------------------------------------------------
  def call_http_reading
    buffer    = "\000" * call_query_info_size
    read_size = "\000" * 16
    ret = HTTP_READING.call(@h_request, buffer, buffer.size, read_size)
    raise NetReadingError if ret == 0
    @data = buffer[0, read_size.unpack("L!")[0]]
  end
  #--------------------------------------------------------------------------
  # ■ 接続を全て切る
  #--------------------------------------------------------------------------
  def call_net_close
    INTERNET_CLOSE.call(@h_request)
    INTERNET_CLOSE.call(@h_http)
    INTERNET_CLOSE.call(@h_net)
  end
  #--------------------------------------------------------------------------
  # ■ URLのサーバー名とパス名を強引に解析
  #--------------------------------------------------------------------------
  def url_crack(url)
    data = url.split("/", 4)
    @server = data[2]
    @path   = data[3]
    @secure = data[0] =~ /https/ ? true : false
  end
  #--------------------------------------------------------------------------
  # ■ Base64方式エンコード
  #--------------------------------------------------------------------------
  def self.base64_encode(data)
    [data].pack("m0")
  end
  #--------------------------------------------------------------------------
  # ■ URLエンコード
  #--------------------------------------------------------------------------
  def self.url_encode(text)
    ret = ""
    text.split("").each do |char|
      if char =~ /[a-zA-Z0-9\.\-_~]/
        ret += char
      else
        ret += (char.unpack("C*").collect { |c| sprintf("%%%02X", c)}).join
      end
    end
    return ret
  end
end



module Log
  #--------------------------------------------------------------------------
  # ■ エラーを記録
  #--------------------------------------------------------------------------
  def self.error(err)
    save(err.class.to_s + " ... " + err.message)
  end
  #--------------------------------------------------------------------------
  # ■ ログを保存
  #--------------------------------------------------------------------------
  def self.save(text)
    text = text[0, 240] if text.size > 240
    text.gsub!(/\r|\n/, "")
    write = Time.now.to_s + " " + text + "\r\n"
    begin
      Dir.mkdir("Log") unless FileTest.exist?("Log/")
      File.open("Log/ErrorLog.txt", "r+") do |file|
        val = file.read
        val = write + val   # 先頭行に追記
        file.pos = 0
        file.write(val)
      end
    rescue Errno::ENOENT    # ログファイルが無い時、作成してリトライ
      File.open("Log/ErrorLog.txt", "w").close
      retry
    end
  end
end



class Game_Interpreter
  #--------------------------------------------------------------------------
  # ● 注釈
  #--------------------------------------------------------------------------
  alias sui_sv_command_108 command_108
  def command_108
    @params.each do |param|
      if param =~ /\A([A-Z]+)\s+([0-9\s-]+)\z/
        case $1
          when "GET";     SV.get($2)
          when "UPDATE";  SV.update($2)
          when "ADD";     SV.add($2)
          when "MAX";     SV.max($2)
          when "MIN";     SV.min($2)
          when "MAXRANK"; SV.maxrank($2)
          when "MINRANK"; SV.minrank($2)
        end
      end
    end
    sui_sv_command_108
  end
end
