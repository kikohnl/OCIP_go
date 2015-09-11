package main

import (
    "fffilimonov/ocip"
    "os"
)

func main() {
    var file string = "config"
    Config := ocip.ReadConfig(file)
    var USERID,MODE,DST string
    larg:=len(os.Args)
    if larg > 1 {
        MODE = os.Args[1]
    }
    if larg > 2 {
        USERID = ocip.ConcatStr("",os.Args[2],"@spb.swisstok.ru")
    }
    if larg > 3 {
        DST = os.Args[3]
    }
    if MODE == "status" {
        ocip.OCIPsend(Config,USERID,"UserCallForwardingAlwaysGetRequest")
    }
    if MODE == "false" {
        ocip.OCIPsend(Config,USERID,"UserCallForwardingAlwaysModifyRequest","isActive=false")
    }
    if MODE == "true" {
        ocip.OCIPsend(Config,USERID,"UserCallForwardingAlwaysModifyRequest","isActive=true",ocip.ConcatStr("","forwardToPhoneNumber=",DST))
    }
}
