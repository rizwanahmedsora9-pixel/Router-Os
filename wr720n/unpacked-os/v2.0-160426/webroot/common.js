//setTagStr(document,'ntw_common_js')
var str_pages = parent.pages_js;
var str_main = parent.str_main;
var str_js = parent.str_js;
var VER_NUMBER;

function setTagStr(obj,page) {
	var e, ee;
	var i, n;
	var items;
	//判断浏览器的版本，如果低于IE5.5，不支持，added by ZQQ，09.05.05
	var sUserAgent = window.navigator.userAgent;
	if (sUserAgent.indexOf("MSIE") > 0)
	{
		var n = sUserAgent.indexOf("MSIE")+5;
		var sVer = sUserAgent.substring(n);
		n = sVer.indexOf(";");
		VER_NUMBER = sVer.substring(0,n);
		if(VER_NUMBER < 5.5)
		{
			//如果IE 的版本小于 5.5 则下面的替换就不需要执行了，因为在5.0下undefined无定义，函数出错
			return;
		}
	}
	//end added by ZQQ

	if(str_pages==undefined||str_main==undefined)
	{
		//for popupSiteSurveyRpm.htm 2008-09-03, lzy
		str_pages = pages_js;
		str_main = str_main;
	}

	for ( tag in str_pages[page] )
	{
		try{
			items = obj.all[tag];
			
			if(undefined != items.length && items.length > 0){
				for(i = 0; i < items.length; i++)
				{
					items[i].innerHTML = str_pages[page][tag];
				}
			}
			else{
				items.innerHTML = str_pages[page][tag];
			}
			
			if(!window.ActiveXObject){
				items = obj.getElementsByName(tag);
				for(i = 0; i < items.length; i++)
				{
					items[i].innerHTML = str_pages[page][tag];
				}
			}
		}
		catch(e)
		{
			;
		}
	}
	for ( btn in str_main.btn )
	{
		try
		{
			obj.forms[0][btn].value = str_main.btn[btn];
			//the button with the same name
			if(obj.forms[0][btn].length!=undefined)
			{
				for(i=0;i<obj.forms[0][btn].length;i++)
				{
					obj.forms[0][btn][i].value=str_main.btn[btn];
				}
			}
		}
		catch(e){}
	}
}
function GetMinWidth()
{
    var i=Math.ceil((window.screen.width - 160)*0.55) - 6;
    return i;
}
function LoadHelp(helpFileName)
{
    if(window.parent != window)
    {
        if (window.parent.topFrame.hl != helpFileName)
        {
            window.parent.topFrame.hl = helpFileName;
            window.parent.helpFrame.location.href = "/help/" + helpFileName;
        }
    }
    return true;
}

function resize(obj)
{
    var minWidth = GetMinWidth();
    if (window.document.body.offsetWidth > minWidth)
    {
		obj.document.getElementById("autoWidth").style.width="100%";
    }
    else
    {
		obj.document.getElementById("autoWidth").style.width=minWidth;
    }
        return true; 
}
function resizeHelp(obj)
{
    if (window.document.body.offsetWidth > 290)
    {
        obj.autoWidth.style.width = "100%";
    }
    else
    {
        obj.autoWidth.style.width = 290;
    }
    return true; 
}
function LoadNext(FileName) 
{
    if(window.parent != window)
    window.parent.mainFrame.location.href = FileName;
    return true; 
}
function lastipverify(lastip,nMin,nMax)
{
    var c;
    var n = 0;
    var ch = "0123456789";
    if(lastip.length = 0)
    return false;
    for (var i = 0; i < lastip.length; i++)
    {
        c = lastip.charAt(i);
        if (ch.indexOf(c) == -1)
        return false;
    }
    if (parseInt(lastip, 10) < nMin || parseInt(lastip, 10) > nMax)
        return false;
    
    return true;
}
function is_lastip(lastip_string,nMin,nMax)
{
    if(lastip_string.length == 0)
    {
        alert(js_input_ip0="Please input an IP address(1-254)!");
        return false;
    }
    if (!lastipverify(lastip_string,nMin,nMax))
    {
        alert(js_bad_ip0="The IP address is invalid, please input another one(1-254)!");
        return false;
    }
    return true;
}
function maskipverify(ip_string)
{
    var c;
    var n = 0;
    var ch = ".0123456789";
    if (ip_string.length < 7 || ip_string.length > 15)
    return false;
    for (var i = 0; i < ip_string.length; i++)
    {
        c = ip_string.charAt(i);
        if (ch.indexOf(c) == -1)
            return false;
        else
        {
            if (c == '.')
            {
                if(ip_string.charAt(i+1) != '.')
                n++;
                else
                return false;
            }
        }
    }
    if (n != 3)
    return false;
    if (ip_string.indexOf('.') == 0 || ip_string.lastIndexOf('.') == (ip_string.length - 1))
    return false;
    szarray = [0,0,0,0];
    var remain;
    var i;
    for(i = 0; i < 3; i++)
    {
        var n = ip_string.indexOf('.');
        szarray[i] = ip_string.substring(0,n);
        remain = ip_string.substring(n+1);
        ip_string = remain;
    }
    szarray[3] = remain;    //added by ZQQ, the IP is devided to four parts
    for(i = 0; i < 4; i++)
    {
        if (szarray[i] < 0 || szarray[i] > 255)
        {
            return false;
        }
    }
    return true;
}
function ipverify(ip_string)
{
    var c;
    var n = 0;
    var ch = ".0123456789";
    if (ip_string.length < 7 || ip_string.length > 15)
    return false;
    for (var i = 0; i < ip_string.length; i++)
    {
        c = ip_string.charAt(i);
        if (ch.indexOf(c) == -1)
        return false;
        else
        {
            if (c == '.')
            {
                if(ip_string.charAt(i+1) != '.')
                    n++;
                else
                    return false;
            }
        }
     }   
    if (n != 3)
    return false;
    if (ip_string.indexOf('.') == 0 || ip_string.lastIndexOf('.') == (ip_string.length - 1))
    return false;
    szarray = [0,0,0,0];
    var remain;
    var i;
    for(i = 0; i < 3; i++)
    {
        var n = ip_string.indexOf('.');
        szarray[i] = ip_string.substring(0,n);
        remain = ip_string.substring(n+1);
        ip_string = remain;
    }
    szarray[3] = remain;
    for(i = 0; i < 4; i++)
    {
        if (szarray[i] < 0 || szarray[i] > 255)
        {
            return false;
        }
    }
    if(szarray[0]==127 && szarray[1]==0 && szarray[2]==0) //检查环回地址
    {
        return false;
    }
    if(szarray[0] >= 224 && szarray[0] <=239) //检查多播
    {
        return false;
    }	
    return true;
}
function is_ipaddr(ip_string)
{
    if(ip_string.length == 0)
    {
        alert(js_input_ip1="Please input an IP address!");
        return false;
    }
    if (!ipverify(ip_string))
    {
        alert(js_bad_ip1="The IP address is invalid, please input another one!");
        return false;
    }
    return true;
}
function is_gatewayaddr(gateway_string)
{
    if(gateway_string.length == 0)
    {
        alert(js_input_gateway="Please input the Gateway!");
        return false;
    }
    if (!ipverify(gateway_string))
    {
        alert(js_bad_gateway="The gateway is invalid, please input another one!");
    return false;
    }
    return true;
}
function is_dnsaddr(dns_string)
{
    if(dns_string.length == 0)
    {
        alert(js_input_dns="Please input the DNS server address (for example 202.96.134.133)!");
        return false;
    }
    if (!ipverify(dns_string))
    {
        alert(js_bad_dns="The DNS server address is invalid, please input another one(for example 202.96.134.133)!");
        return false;
    }
    return true;
}
function is_domain(domain_string)
{
    var c;
    var ch = "-.ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
    for (var i = 0; i < domain_string.length; i++)
    {
        c = domain_string.charAt(i);
        if (ch.indexOf(c) == -1)
        {
            alert(js_illegal_input="The input value contain illegal characters, please input another one!");
            return false;
        }
    }
    return true;
}
function is_digit(digit_string)
{
    var c;
    var ch = "0123456789";
    for (var i = 0; i < digit_string.length; i++)
    {
        c = digit_string.charAt(i);
        if(c == " "&& i ==1)
        {
            continue;
        }
        if(i > 0)
        {
            if(digit_string.charAt(i-1) == " " && c == " ")
            {
                continue;
            }
            if(digit_string.charAt(i-1) != " " && c == " ")
            {
                alert(js_illegal_input="The input value contain illegal characters, please input another one!");
                return false;
            }
        }
        if(ch.indexOf(c) == -1 )
        {
            if(c !=" ")
            {
                alert(js_illegal_input="The input value contain illegal characters, please input another one!");
                return false;
            }
        }
    }
    return true;
}
function portverify(port_string)
{
    var c;
    var ch = "0123456789";
    if(port_string.length == 0)
    return false;
    for (var i = 0; i < port_string.length; i++)
    {
        c = port_string.charAt(i);
        if (ch.indexOf(c) == -1)
        return false;
    }
    if (parseInt(port_string, 10) <= 0 || parseInt(port_string, 10) >=65535)
    {
        return false;
    }
    return true;
}
function is_port(port_string)
{
    if(port_string.length == 0)
    {
        alert(js_input_port="Please input the port number (1-65534)!");
        return false;
    }
    if (!portverify(port_string))
    {
        alert(js_bad_port="The port number is invalid, please input another one(1-65534)!");
        return false;
    }
    return true;
}
function is_number(num_string,nMin,nMax)
{
    var c;
    var ch = "0123456789";
    for (var i = 0; i < num_string.length; i++)
    {
        c = num_string.charAt(i);
        if (ch.indexOf(c) == -1)
        {
            alert(js_illegal_input="The input value contain illegal characters, please input another one!");
            return false;
        }
    }
    if(parseInt(num_string, 10) < nMin || parseInt(num_string, 10) > nMax)
    {
        return false;
    }
    return true;
}
function is_maskaddr(mask_string)
{
    if(mask_string.length == 0)
    {
        alert(js_input_mask="Please input the Subnet Mask (for example: 255.255.255.0)!");
        return false;
    }
    if (!maskipverify(mask_string))
    {
        alert(js_bad_mask="The Subnet Mask is invalid, please input another one (for example: 255.255.255.0)!");
        return false;
    }
    return true;
}
function macverify(mac_string)
{
    var c;
    var n = 0;
    var ch = "-0123456789ABCDEFabcdef";
    var remain;
    var fs = 0;
    szarray = [0,0,0,0,0,0];
    if (mac_string.length != 17)
    {
        alert(js_bad_mac_format="The MAC address format is invalid! The valid format is '00-00-00-00-00-00'.");
        return false;
    }
    //added by ZQQ,09.08.13  if mac=00-00-00-00-00-00, return;
    if(mac_string == "00-00-00-00-00-00")
	{
		alert(js_inv_mac_zero = "Invalid MAC address, please input again!");
		return false;
	}
    for (var i = 0; i < mac_string.length; i++)
    {
        c = mac_string.charAt(i);
        if (ch.indexOf(c) == -1)
        {
            alert(js_invalid_mac="Invalid MAC address, please input another one!");
            return false;
        }
        else
        {
            if (c == '-')
            n++;
        }
    }
    if (n != 5)
    {
        alert(js_bad_mac_format="The MAC address format is invalid! The valid format is '00-00-00-00-00-00'.");
        return false;
    }
    for(var i = 2; i < 17; i += 3)
    {
        if (mac_string.charAt(i) != '-')
        {
            alert(js_bad_mac_format="The MAC address format is invalid! The valid format is '00-00-00-00-00-00'.");
            return false;
        }
    }
    mac_string = mac_string.toLowerCase();
    for(var j = 0; j < 5; j++)
    {
        var n = mac_string.indexOf("-");
        szarray[j] = mac_string.substring(0,n);
        remain = mac_string.substring(n+1);
        mac_string = remain;
    }
    szarray[5] = mac_string;
    var mac=/[0-9A-Fa-f]{1}[13579bdfBDF]{1}/g;
    if(null!=mac.exec(szarray[0]))
    {
        for(var k = 0; k < 6; k++)
        {
            if (szarray[k] == "ff")
            {
                fs++;
            }
        }
        if(fs == 6)
        {
            alert(js_broadcast_mac="The MAC address is a broadcast MAC address, please input again!");
            return false;
        }

        alert(js_multi_mac="The MAC address is a multicast MAC address, please input again!");
        return false;
    }

    return true;
}
function is_macaddr(mac_string)
{
    if(mac_string.length == 0)
    {
        alert(js_input_mac="Please input a MAC address!");
        return false;
    }
    if (!macverify(mac_string))
    {
        return false;
    }
    return true;
}
function charCompare(szname,limit)
{           
    var c;
    var l=0;
    var ch = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789@^-_.><,[]{}?/+=|\\'\":;~!#$%()` & ";
    if(szname.length > limit)
    return false;
    for (var i = 0; i < szname.length; i++)
    {
        c = szname.charAt(i);
        if (ch.indexOf(c) == -1)
        {
            l += 2;
        }
        else
        {
            l += 1;
        }
        if ( l > limit)
        {
            return false;
        }
    }
    return true;
}
function is_hostname(name_string, limit)
{
    if(!charCompare(name_string,limit))
    {
        if(limit == 30)
			alert(js_input_msg="You can input up to 30 characters, please input again!");
		else 
			alert(js_input_too_many="You input too many characters, please input again!");
        return false;
    }
    else
    return true;
}
function is_port_range(port_value)
{
    if(port_value < 1 || port_value > 65534)
    {
        alert(js_bad_port="Invalid port value! The port must be between 1~65534, please input another one!");
        return false;
    }
    else
    {
        return true;
    }
}
function is_floatnumber(num_string,dMin,dMax)
{
	var c;
	var n = 0;
	var ch = ".0123456789";
	for (var i = 0; i < num_string.length; i++)
	{
		c = num_string.charAt(i);
		if (ch.indexOf(c) == -1)
			return false;
		else
		{
			if (c == '.')
				n++;
		}
	}
	if (n > 1)
		return false;

	if(parseFloat(num_string) < dMin || parseFloat(num_string) > dMax)
		return false;

	return true;
}


var transMatrixHTML = new Array(
	/&/g, "&amp;",
	/\\/g, "&#92;",
	/'/g, "&#39;",
	/"/g, "&quot;",
	/</g, "&lt;",
	/>/g, "&gt;",
	/ /g, "&nbsp;"
);
function escapeHtml(str)
{
    var r = str.toString();
	for (var i = 0; i < transMatrixHTML.length; i+=2)
	{
		r = r.replace(transMatrixHTML[i], transMatrixHTML[i+1]);
	}
	return r;
}