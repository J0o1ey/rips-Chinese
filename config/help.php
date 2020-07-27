<?php
/** 

RIPS - A static source code analyser for vulnerabilities in PHP scripts 
	by Johannes Dahse (johannes.dahse@rub.de)
			
			
Copyright (C) 2012 Johannes Dahse

This program is free software; you can redistribute it and/or modify it under the terms of the GNU General Public License as published by the Free Software Foundation; either version 3 of the License, or (at your option) any later version.

This program is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for more details.

You should have received a copy of the GNU General Public License along with this program; if not, see <http://www.gnu.org/licenses/>.	

**/
header("Content-type: text/html; charset=utf-8"); 
$HELP_XSS = array(
'description' => '攻击者可能在这个安全漏洞的客户端浏览器中执行任意的HTML / JavaScript代码。污染数据是用户的浏览器的用户应用程序嵌入到HTML输出，从而允许攻击者将恶意代码执行。准备一个恶意链接将导致另一个用户的浏览器中点击链接时，该恶意代码的执行。这可能导致钓鱼或Cookie偷窃和会话劫持。',
'link' => 'https://www.owasp.org/index.php/XSS',
'code' => '<?php print("Hello " . $_GET["name"]); ?>',
'poc' => '/index.php?name=<script>alert(1)</script>',
'patchtext' => '在将数据嵌入到输出之前，使用PHP BuudIn函数对所有用户污染数据进行编码。确保设置参数EntType以避免EvEnthDunl注入到现有HTML属性，并指定正确的字符集。',
'patch' => '<?php print("Hello " . htmlentities($_GET["name"], ENT_QUOTES, "utf-8"); ?>' 
);

$HELP_HTTP_HEADER = array(
'description' => '攻击者可以向HTTP响应头注入任意标头。当添加“设置cookie”标题时，当在会话固定攻击中注入标头或帮助时，这可能会被滥用。此外，可以覆盖HTTP响应，并可以注入JavaScript，导致XSS攻击。在4.4.2或5.1.2的PHP版本中，字符\\r（LF CR）可以用于头行终止（跨浏览器）。在PHP低于5.4的情况下，字符R（CR）仍然可以用于头行终止（Chrome，IE）。',
'link' => 'https://www.owasp.org/index.php/HTTP_Response_Splitting',
'code' => '<?php header("Location: ".$_GET["url"]); ?>',
'poc' => '/index.php?url=a%0a%0dContent-Type:%20text/html%0a%0d%0a%0d<script>alert(1)</script>',
'patchtext' => '更新PHP以防止报头注入或实现白名单。',
'patch' => '<?php if(!in_array($_GET["url"], $whitelist)) exit; ?>'
);

$HELP_SESSION_FIXATION = array(
'description' => '攻击者可以强制用户使用特定的会话ID。一旦用户登录，攻击者可以使用先前固定的会话ID访问帐户。',
'link' => 'https://www.owasp.org/index.php/Session_fixation',
'code' => '<?php setcookie("PHPSESSID", $_GET["sessid"]); ?>',
'poc' => '/index.php?sessid=1f3870be274f6c49b3e31a0c6728957f',
'patchtext' => '不要使用用户提供的会话令牌。',
'patch' => 'No code.'
);

$HELP_CODE = array(
'description' => '攻击者可能使用此漏洞执行任意PHP代码。用户污染的数据被嵌入到一个函数中，该函数在运行时编译PHP代码并执行它，从而允许攻击者注入自己要执行的PHP代码。此漏洞可能导致服务器完全被入侵。',
'link' => 'https://www.owasp.org/index.php/Code_Injection',
'code' => '<?php eval("\$color = \'" . $_GET["color"] . "\';"); ?>',
'poc' => '/index.php?color=\';phpinfo();//',
'patchtext' => '用正则表达式（例如仅字母数字）或数组为你的代码构建一个白名单。不要试图仅仅给PHP的evil函数设置黑名单.',
'patch' => '<?php $colors = array("blue", "red"); if(!in_array($_GET["color"], $colors)) exit; ?>'
);

$HELP_REFLECTION = array(
'description' => '攻击者可能使用此漏洞执行任意函数。用户污秽数据用作函数名。这可能导致应用程序的执行特殊行为。',
'link' => 'https://www.owasp.org/index.php/Reflection_injection',
'code' => '<?php call_user_func($_GET["func"]); ?>',
'poc' => '/index.php?func=phpinfo',
'patchtext' => '给可信的函数设置白名单',
'patch' => '<?php $funcs = array("test1", "test2"); if(!in_array($_GET["func"], $funcs)) exit; ?>'
);

$HELP_FILE_INCLUDE = array(
'description' => '攻击者可能包括本地或远程PHP文件或读取带有此漏洞的非PHP文件。使用黑客的恶意数据。将对该文件中的PHP代码进行执行，将非PHP代码嵌入到输出中。此漏洞可能导致服务器完全倒戈。',
'link' => 'http://websec.wordpress.com/2010/02/22/exploiting-php-file-inclusion-overview/',
'code' => '<?php include("includes/" . $_GET["file"]); ?>',
'poc' => '/index.php?file=../../../../../../../etc/passwd',
'patchtext' => '为文件名建立一个白名单。不要仅将文件名限制为特定路径或扩展名。',
'patch' => '<?php $files = array("index.php", "main.php"); if(!in_array($_GET["file"], $files)) exit; ?>'
);

$HELP_FILE_READ = array(
'description' => '攻击者可能会读取带有此漏洞的本地文件。当创建将被打开和读取的文件名时，使用用户的恶意数据，从而允许攻击者读取可能导致新攻击向量的Web服务器上的源代码和其他任意文件。例如，攻击者可以检测源代码文件中的新漏洞或读取用户凭据。',
'link' => '',
'code' => '<?php echo file_get_contents("files/" . $_GET["file"]); ?>',
'poc' => '/index.php?file=../../../../../../../etc/passwd',
'patchtext' => '为文件名建立一个白名单。不要仅将文件名限制为特定路径或扩展名。',
'patch' => '<?php $files = array("index.php", "main.php"); if(!in_array($_GET["file"], $files)) exit; ?>'
);

$HELP_FILE_AFFECT = array(
'description' => '攻击者可能会写入任意文件或将任意代码注入到具有此漏洞的文件中。当创建将被打开的文件名或创建将写入文件的字符串时使用用户注入的恶意数据。攻击者可以尝试在PHP文件中编写任意PHP代码，从而完全危及服务器。',
'link' => '',
'code' => '<?php $h = fopen($_GET["file"], "w"); fwrite($h, $_GET["data"]); ?>',
'poc' => '/index.php?file=shell.php&data=<?php phpinfo();?>',
'patchtext' => '为正文件名建立一个白名单。不要仅将文件名限制为特定路径或扩展名。如果写入PHP文件，请确保攻击者不能编写自己的PHP代码。使用带有数组或正则表达式的白名单（例如仅字母数字）。',
'patch' => '<?php $files = array("index.php", "main.php"); if(!in_array($_GET["file"], $files)) exit; ?>'
);

$HELP_EXEC = array(
'description' => '攻击者可能使用此漏洞执行任意系统命令。当创建将在底层操作系统上执行的命令时，使用用户恶意数据。此漏洞可能导致服务器完全倒戈。',
'link' => '',
'code' => '<?php exec("./crypto -mode " . $_GET["mode"]); ?>',
'poc' => '/index.php?mode=1;sleep 10;',
'patchtext' => 'Limit the code to a very strict character subset or build a whitelist of allowed commands. Do not try to filter for evil commands. Try to avoid the usage of system command executing functions if possible.',
'patch' => '<?php $modes = array("r", "w", "a"); if(!in_array($_GET["mode"], $modes)) exit; ?>'
);

$HELP_DATABASE = array(
'description' => '攻击者可能使用此漏洞在数据库服务器上执行任意SQL命令。在创建数据库管理系统（DBMS）的数据库查询时，使用用户提交的恶意数据。攻击者可以注入自己的SQL语法，从而启动查询、插入或删除数据库条目或根据查询、DBMS和配置攻击底层操作系统。',
'link' => 'https://www.owasp.org/index.php/SQL_Injection',
'code' => '<?php mysql_query("SELECT * FROM users WHERE id = " . $_GET["id"]); ?>',
'poc' => '/index.php?id=1 OR 1=1--',
'patchtext' => '在将语句其嵌入到查询之前，总是将预期字符串嵌入到引用中，然后用PHP BuudIn函数来跳过字符串。总是在没有引用的情况下嵌入要使用的整数，并在将数据嵌入到查询之前，将数据类型化为整数。逃避数据，但不引用它嵌入是不安全的。',
'patch' => '<?php mysql_query("SELECT * FROM users WHERE id = " . (int)$_GET["id"]); '."\n".' mysql_query("SELECT * FROM users WHERE name = \'" . mysql_real_escape_string($_GET["name"]) . "\'"); ?>'
);

$HELP_XPATH = array(
'description' => '攻击者可能使用此漏洞执行任意XPath表达式。当创建在XML资源上执行的XPath表达式时，使用用户的恶意数据。攻击者可以注入自己的XPath语法来读取任意XML条目。',
'link' => 'http://packetstormsecurity.org/files/view/33380/Blind_XPath_Injection_20040518.pdf',
'code' => '<?php $ctx->xpath_eval("//user[name/text()=\'" . $_GET["name"] . "\']/account/text()"); ?>',
'poc' => '/index.php?name=\' or \'\'=\'',
'patchtext' => '在嵌入到表达式中之前，总是将预期字符串嵌入到引用中，然后用PHP BuudIn函数来跳过字符串。总是在没有引用的情况下嵌入期望的整数，并在将数据嵌入到表达式之前将数据类型化为整数。逃避数据，但不引用它嵌入是不安全的。',
'patch' => '<?php $ctx->xpath_eval("//user[name/text()=\'" . addslashes($_GET["name"]) . "\']/account/text()"); ?>'
);

$HELP_LDAP = array(
'description' => '攻击者可能使用此漏洞执行任意LDAP表达式。当在LDAP服务器上执行LDAP筛选器时，使用用户污染的数据。攻击者可以注入自己的LDAP语法来读取任意LDAP条目。',
'link' => 'http://www.blackhat.com/presentations/bh-europe-08/Alonso-Parada/Whitepaper/bh-eu-08-alonso-parada-WP.pdf',
'code' => '<?php ldap_search($ds, $dn, "(&(sn=person)(person=".$_GET["person"]."))"); ?>',
'poc' => '/index.php?person=*',
'patchtext' => '预期字符串不会嵌入到LDAP中的引号中。将输入字符集限制为字母数字（如果可能的话），以防止过滤器语法的注入。',
'patch' => '<?php if(!preg_match(\'/^[a-z0-9]+$/\', $_GET["person"])) exit; ?>'
);

$HELP_CONNECT = array(
'description' => '攻击者可能会更改正在使用此漏洞传输的连接处理参数或数据。当选择参数或创建将被传输的数据时，使用受污染的数据，从而允许攻击者改变参数。取决于连接的类型，这可能会导致进一步的攻击。',
'link' => '',
'code' => 'Can not be generalized.',
'poc' => 'Can not be generalized.',
'patchtext' => 'Can not be generalized.',
'patch' => 'Can not be generalized.'
);

$HELP_POP = array(
'description' => '当UnServices被unSerialIZE（）函数解析时，攻击者可能会通过提供将在当前应用范围中使用的序列化对象来滥用此功能。这些对象只能是该应用程序类的实例。当这些对象在非序列化过程中复活时，会自动调用这些类中的一些类，例如“γ-WAKEUP（））或“γ-销毁”（），而这些攻击对象指定的对象变量可能会导致这些小工具中的漏洞。',
'link' => 'https://media.blackhat.com/bh-us-10/presentations/Esser/BlackHat-USA-2010-Esser-Utilizing-Code-Reuse-Or-Return-Oriented-Programming-In-PHP-Application-Exploits-slides.pdf',
'code' => '<?php
class foo { 
	public $file = "test.txt";
	public $data = "text"; 
	function __destruct() 
	{ 
		file_put_contents($this->file, $this->data); 
	} 
} 
$a = unserialize($_GET["s"]);
?>',
'poc' => '/index.php?s=O:3:"foo":2:{s:4:"file";s:9:"shell.php";s:4:"data";s:29:"<?php passthru($_GET["c"]);?>";}',
'patchtext' => '防止使用非序列化，因为它包含更多的缺陷。',
'patch' => 'No code.'
);
?>