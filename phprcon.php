<?php
// ************************************************************************
//PHPrcon - PHP script collection to remotely administrate and configure Halflife and HalflifeMod Servers through a webinterface
//Copyright (C) 2002  Henrik Beige
//
//This library is free software; you can redistribute it and/or
//modify it under the terms of the GNU Lesser General Public
//License as published by the Free Software Foundation; either
//version 2.1 of the License, or (at your option) any later version.
//
//This library is distributed in the hope that it will be useful,
//but WITHOUT ANY WARRANTY; without even the implied warranty of
//MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
//Lesser General Public License for more details.
//
//You should have received a copy of the GNU Lesser General Public
//License along with this library; if not, write to the Free Software
//Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
// ************************************************************************
//
// 2009 by |PJ|ShOrTy
//        fixed protocol since HL1 Update 2008
//        fixed multible packet handling
//        added special functions to communicate with amxbans plugin
//
// 2018 by ayy lmao
//	  modified to support xash protocol
//
// 2020 by ayy lmao
//	  improved speed by a lot
//	  fixed every single function so that they actually work
//
// 2022 by bariscodefx
//        fixed every function's $result variable
//
// 2022 by ayy lmao
//        fix formatting

class Rcon
{
    var $connected;
    var $server_ip;
    var $server_password;
    var $server_port;
    var $socket;

    function __construct()
    {
        $this->connected = true;
        $this->server_ip = "";
        $this->server_port = "";
        $this->server_password = "";
    }

    function Connect($server_ip, $server_port, $server_password = "")
    {
        $this->server_ip = gethostbyname($server_ip);
        $this->server_port = $server_port;
        $this->server_password = $server_password;

        $fp = fsockopen("udp://" . $this->server_ip, $this->server_port, $errno, $errstr, 2);
        stream_set_timeout($fp, 2);
        if ($fp) $this->connected = true;
        else
        {
            $this->connected = false;
            return false;
        }
        $this->socket = $fp;
        return true;
    }

    function Disconnect()
    {
        @fclose($this->socket);
        $connected = false;
    }

    function IsConnected()
    {
        return $this->connected;
    }

    public function GetCvar($cvarname)
    {
        if (!$this->connected) return $this->connected;
        if ($cvarname == "") return "";

        $response = $this->RconCommand($cvarname);
        $originalcvar = substr($response, 0, (stripos($response, ":") + 2));
        $value = str_replace($originalcvar, '', $response);

        if (strpos($value, '('))
        {
            return substr($value, 0, strpos($value, '('));;
        }
        else
        {
            return $value;
        }

    }

    function ServerInfo()
    {
        $command = "\xff\xff\xff\xffnetinfo 48 0 4";
        $buffer = $this->Communicate($command);

        if (!$this->connected) return $this->connected;

        if (trim($buffer) == "")
        {
            $this->connected = false;
            return false;
        }

        $serverinfo = explode("\x5c", substr(substr(trim($buffer) , 14) , 8));
        $result = [];

        switch ($serverinfo['2'])
        {
            case "cstrike":
                $game = "Counter-Strike";
            break;

            case "valve":
                $game = "Half-Life";
            break;

            case "dmc":
                $game = "Deatmatch Classic";
            break;

            case "tfc":
                $game = "Team Fortress: Classic";
            break;

            case "ricochet":
                $game = "Ricochet";
            break;
        }

        $result["ip"] = $this->server_ip;
        $result["port"] = $this->server_port;
        $result["name"] = $serverinfo['0'];
        $result["map"] = $serverinfo['8'];
        $result["mod"] = $serverinfo['2'];
        $result["game"] = $game;
        $result["activeplayers"] = $serverinfo['4'];
        $result["maxplayers"] = $serverinfo['6'];
        $result["password"] = $serverinfo['10'];
        return $result;
    }

    function ServerMaps($pagenumber = 0)
    {
        if (!$this->connected) return $this->connected;
        $maps = $this->RconCommand("maps *");

        if (!$maps || trim($maps) == "Bad rcon_password.") return $maps;
        $line = explode("\n", $maps);
        $count = sizeof($line) - 4;

        $result = [];

        for ($i = 0;$i <= $count;$i++)
        {
            $text = $line[$i];
            if (substr($text, -4, 4) == ".bsp")
            {
                $result[$i] = str_replace(".bsp", "", $text);
            }
        }
        return $result;
    }

    function Info()
    {
        if (!$this->connected) return $this->connected;

        $command = "\xff\xff\xff\xffTSource";
        $buffer = $this->Communicate($command);

        if (trim($buffer) == "")
        {
            $this->connected = false;
            return false;
        }

        $result = [];
        $pos = 0;
        $result["type"] = $this->parse_buffer($buffer, $pos, "bytestr");
        $result["version"] = $this->parse_buffer($buffer, $pos, "byte");
        $result["name"] = $this->parse_buffer($buffer, $pos, "string");
        $result["map"] = $this->parse_buffer($buffer, $pos, "string");
        $result["mod"] = $this->parse_buffer($buffer, $pos, "string");
        $result["game"] = $this->parse_buffer($buffer, $pos, "string");
        $result["appid"] = $this->parse_buffer($buffer, $pos, "short");
        $result["activeplayers"] = $this->parse_buffer($buffer, $pos, "byte");
        $result["maxplayers"] = $this->parse_buffer($buffer, $pos, "byte");
        $result["botplayers"] = $this->parse_buffer($buffer, $pos, "byte");
        $result["dedicated"] = $this->parse_buffer($buffer, $pos, "bytestr");
        $result["os"] = $this->parse_buffer($buffer, $pos, "bytestr");
        $result["password"] = $this->parse_buffer($buffer, $pos, "byte");
        $result["secure"] = $this->parse_buffer($buffer, $pos, "byte");
        return $result;
    }

    function parse_buffer($buffer, &$pos, $type)
    {
        $result = "";
        switch ($type)
        {
            case 'string':
                while (substr($buffer, $pos, 1) !== "\x00")
                {
                    $result .= substr($buffer, $pos, 1);
                    $pos++;
                }
            break;
            case 'short':
                $result = ord(substr($buffer, $pos, 1)) + (ord(substr($buffer, $pos + 1, 1)) << 8);
                $pos++;
            break;
            case 'long':
                $result = ord($buffer[$pos]) + (ord($buffer[$pos + 1]) << 8) + (ord($buffer[$pos + 2]) << 16) + (ord($buffer[$pos + 3]) << 24);
                $pos += 3;
            break;
            case 'byte':
                $result = ord(substr($buffer, $pos, 1));
            break;
            case 'bytestr':
                $result = substr($buffer, $pos, 1);
            break;
            case 'float':
                $tmptime = @unpack('ftime', substr($buffer, $pos, 4));
                $result = date('H:i:s', round($tmptime['time'], 0) + 82800);
                $pos += 3;
            break;
        }
        $pos++;
        return $result;
    }

    function Players()
    {
        $server = new Rcon();
        $server->Connect("$this->server_ip", "$this->server_port", "$this->server_password");
        $serverinfo = $server->ServerInfo();

        if (!$this->connected) return $this->connected;

        $command = "\xff\xff\xff\xffnetinfo 48 0 3";
        $buffer = $this->Communicate($command);

        if (trim($buffer) == "")
        {
            $this->connected = false;
            return false;
        }
        $maxplayers = $serverinfo['activeplayers'];
        $players = array_chunk(explode("\x5c", trim(substr($buffer, 14))) , 4);
        $result = [];
        for ($i = 0;$i < $maxplayers;$i++)
        {
            $result[$i]["index"] = $players[$i][3];
            $result[$i]["name"] = $players[$i][0];
            $result[$i]["frag"] = $players[$i][1];
            $result[$i]["time"] = $players[$i][2];
        }
        return $result;
    }

    function RconCommand($rconcommand, $pagenumber = 0, $single = true)
    {
        $command = "\xff\xff\xff\xffrcon $this->server_password $rconcommand\n";

        if (!$this->connected) return $this->connected;
        if ($command != "") fputs($this->socket, $command, strlen($command));
        $buffer = fread($this->socket, 1);
        $status = socket_get_status($this->socket);

        if ($status["unread_bytes"] > 0)
        {
            $buffer .= fread($this->socket, $status["unread_bytes"]);
            if (substr($buffer, -6, 6) == "print\n")
            {
                return;
            }

            while (true)
            {
                $buffer .= fread($this->socket, 128);
                if (substr($buffer, -6, 6) == "print\n")
                {
                    $result = str_replace("\xff\xff\xff\xffprint\n", "", $buffer);
                    return $result;
                }
            }
        }
    }

    function Communicate($command)
    {
        if (!$this->connected) return $this->connected;
        if ($command != "") fputs($this->socket, $command, strlen($command));
        $buffer = fread($this->socket, 1);
        $status = socket_get_status($this->socket);

        if ($status["unread_bytes"] > 0)
        {
            $buffer .= fread($this->socket, $status["unread_bytes"]);
        }

        $bufferret = substr($buffer, 4);
        return $bufferret;
    }
}
?>
