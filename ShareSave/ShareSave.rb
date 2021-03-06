#******************************************************************************
#    RGSS3 - 共有スイッチ＆共有変数
#      Created by 睡工房 (http://hime.be/)
#        License: くいなちゃんライセンス( http://kuina.ch/others/license )
#******************************************************************************
=begin
  ◆機能
    ゲーム全体で共有できるスイッチと変数の機能を追加します。
    また、ツクールのスイッチ・変数を共有化する設定も準備しました。

  ◆使い方
    ・共有スイッチ＆共有変数の保存方法
      自動保存になっている場合、値の設定時にファイルが保存されます。
      オフにした場合は、イベントコマンドのスクリプトで保存処理を実行して下さい。
          SUI_SHARE.save

    ・値の設定方法
    　イベントコマンドのスクリプト欄に以下のように記述してください。
    　※共有スイッチ・共有変数のIDには文字列の指定も可能です。
  　　１．スイッチの設定
          $ssw[1] = true
          $ssw["love"] = false

    　２．変数の設定
          $svar[1] = 100
          $svar["love"] = 100

    　３．スイッチ・変数の参照
          $ssw[1]
          $svar["love"]

    ・ツクールのスイッチ・変数を共有化した場合
      上記の方法以外に、普通のイベントコマンドで使用可能です。
      ※文字列IDの共有スイッチ及び共有変数はイベントコマンドからは扱えません。

    ・その他
      共有スイッチ及び共有変数には文字列を保存しても問題ありません。
          $ssw[1] = "I love you"
          $svar[1] = "あいらびゅー"
=end


module SUI_SHARE
  # 共有スイッチ＆共有変数の自動保存
  # trueにした場合、値を設定したときに自動的にセーブファイルが更新されます。
  # falseにした場合、スクリプトで保存処理を実行してください。（使い方参照）
  AUTOSAVE = true
  
  # 共通化したいスイッチのIDを設定してください。
  # ここで設定していないIDの共有スイッチは、イベントコマンドとは別物になります。
  # SWITCHES = [1,2,100]
  SWITCHES = []
  
  # 共通化したい変数のIDを設定してください。
  # ここで設定していないIDの共有変数は、イベントコマンドとは別物になります。
  # COMMON_VARIABLE = [1,2,100]
  VARIABLES = []
end


class Share_Save < Hash
  def []=(key, value)
    super(key, value)
    SUI_SHARE.save if SUI_SHARE::AUTOSAVE
    on_change
  end
  #--------------------------------------------------------------------------
  # ● スイッチの設定時の処理
  #--------------------------------------------------------------------------
  def on_change
    $game_map.need_refresh = true
  end
end


class Game_Switches
  #--------------------------------------------------------------------------
  # ● スイッチの取得
  #--------------------------------------------------------------------------
  alias :sui_get :[]
  def [](key)
    return $ssw[key] if SUI_SHARE::SWITCHES.include?(key)
    sui_get(key)
  end
  #--------------------------------------------------------------------------
  # ● スイッチの設定
  #--------------------------------------------------------------------------
  alias :sui_set :[]=
  def []=(key, value)
    return $ssw[key] = value if SUI_SHARE::SWITCHES.include?(key)
    sui_set(key, value)
  end
end


class Game_Variables
  #--------------------------------------------------------------------------
  # ● 変数の取得
  #--------------------------------------------------------------------------
  alias :sui_get :[]
  def [](key)
    return $svar[key] if SUI_SHARE::VARIABLES.include?(key)
    sui_get(key)
  end
  #--------------------------------------------------------------------------
  # ● 変数の設定
  #--------------------------------------------------------------------------
  alias :sui_set :[]=
  def []=(key, value)
    return $svar[key] = value if SUI_SHARE::VARIABLES.include?(key)
    sui_set(key, value)
  end
end


module SUI_SHARE
  FILENAME = "ShareSave.rvdata"
  #--------------------------------------------------------------------------
  # ● 共通セーブファイルの初期化
  #--------------------------------------------------------------------------
  def self.init
    $ssw = Share_Save.new(false)
    $svar = Share_Save.new(0)
  end
  #--------------------------------------------------------------------------
  # ● 共通セーブファイルの保存
  #--------------------------------------------------------------------------
  def self.save
    save_data([$ssw, $svar], FILENAME)
  end
  #--------------------------------------------------------------------------
  # ● 共通セーブファイルの読み込み
  #--------------------------------------------------------------------------
  def self.load
    return init unless FileTest.exist?(FILENAME)
    $ssw, $svar = load_data(FILENAME)
  end
end


#--------------------------------------------------------------------------
# ● 共有スイッチ＆共有変数の読み込み
#--------------------------------------------------------------------------
SUI_SHARE.load
