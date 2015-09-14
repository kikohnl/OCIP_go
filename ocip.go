
package ocip

import (
    "crypto/md5"
    "crypto/sha1"
    "encoding/hex"
    "bufio"
    "encoding/xml"
    "fmt"
    "gopkg.in/gcfg.v1"
    "math/rand"
    "os"
    "strings"
    "net"
    "time"
)

type ConfigT struct {
    Main struct {
        User string
        Password string
        Host string
        OCIPPort string
    }
}

func ReadConfig(Configfile string) ConfigT {
    var Config ConfigT
    err := gcfg.ReadFileInto(&Config, Configfile)
    if err != nil {
        LogErr(err,"Config file is missing:", Configfile)
        os.Exit (1)
    }
    return Config
}

func ConcatStr(sep string, args ... string) string {
    return strings.Join(args, sep)
}

func MakeDigest(PASS string,NONCE string) string {
    hpass := sha1.Sum([]byte(PASS))
    spass:=hex.EncodeToString(hpass[:])
    cnonce:=ConcatStr(":",NONCE,spass)
    hresp := md5.Sum([]byte(cnonce))
    resp:=hex.EncodeToString(hresp[:])
    return resp
}

var letters = []rune("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ")
func randSeq(n int) string {
    rand.Seed(time.Now().UnixNano())
    b := make([]rune, n)
    for i := range b {
        b[i] = letters[rand.Intn(len(letters))]
    }
    return string(b)
}

func LogErr (err error,args ... string) {
    fmt.Fprint(os.Stderr,time.Now(),args,err,"\n")
}

func LogOut (log string) {
    fmt.Fprint(os.Stdout,log)
}

type OCIP struct {
    Nonce string `xml:"command>nonce"`
}

func ParseOCIP (data []byte) OCIP {
    var ocip OCIP
    xml.Unmarshal(data, &ocip)
    return ocip
}

func OCIPsend(Config ConfigT,COMMAND string,args ...string){
    var SESSION string = randSeq(10)
    var HEAD string = ConcatStr("","<?xml version=\"1.0\" encoding=\"ISO-8859-1\"?><BroadsoftDocument protocol = \"OCI\" xmlns=\"C\" xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\"><sessionId xmlns=\"\">",SESSION,"</sessionId>")
    var dialer net.Dialer
    dialer.Timeout=time.Second
    chandesc, err := dialer.Dial("tcp",ConcatStr(":",Config.Main.Host,Config.Main.OCIPPort))
    if err != nil {
        LogErr (err,"OCIP connection")
    }
    chandesc.SetReadDeadline(time.Now().Add(time.Second))
    AUTH := ConcatStr("","<command xsi:type=\"AuthenticationRequest\" xmlns=\"\" xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\"><userId>",Config.Main.User,"</userId></command></BroadsoftDocument>")
    fmt.Fprintf(chandesc,"%s%s",HEAD,AUTH)
    chanreader := bufio.NewReader(chandesc)
    status,err := chanreader.ReadString('\n')
    status,err = chanreader.ReadString('\n')
    ocip := ParseOCIP([]byte(status))
    responce := MakeDigest(Config.Main.Password,ocip.Nonce)
    LOGIN := ConcatStr("","<command xsi:type=\"LoginRequest14sp4\" xmlns=\"\" xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\"><userId>",Config.Main.User,"</userId><signedPassword>",responce,"</signedPassword></command></BroadsoftDocument>")
    fmt.Fprintf(chandesc,"%s%s",HEAD,LOGIN)
    status,err = chanreader.ReadString('\n')
    status,err = chanreader.ReadString('\n')
    var ARGS string
    separated := strings.Split(strings.Join(args,"="),"=")
    if len(separated) > 1 {
        for i:=0;i<len(separated);i=i+2 {
            ARGS = ConcatStr("",ARGS,"<",separated[i],">",separated[i+1],"</",separated[i],">")
        }
    }
    REQ := ConcatStr("","<command xsi:type=\"",COMMAND,"\" xmlns=\"\" xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\"><userId>",USERID,"</userId>",ARGS,"</command></BroadsoftDocument>")
    fmt.Fprintf(chandesc,"%s%s",HEAD,REQ)
    status,err = chanreader.ReadString('\n')
    status,err = chanreader.ReadString('\n')
    LogOut(status)
    LOGOUT := ConcatStr("","<command xsi:type=\"LogoutRequest\" xmlns=\"\" xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\"><userId>",Config.Main.User,"</userId></command></BroadsoftDocument>")
    fmt.Fprintf(chandesc,"%s%s",HEAD,LOGOUT)
    chandesc.Close()
}
