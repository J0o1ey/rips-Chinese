<?php
/** 
RIPPS——PHP脚本中的静态源代码分析器

作者:Johannes Dahse 汉化者:J0o1ey' QQ547006660

这个程序是免费软件；您可以根据自由软件基金会发布的GNU通用公共许可证的条款重新分发和/或修改它；许可证的第三版，或者（在您的选择）任何其他版本。

这个程序被分发，希望它是有用的，但是没有任何保证；甚至没有对适销性或适合特定用途的默示保证。详情请参阅GNU通用公共许可证。


**/

include 'config/general.php';

?><html>
<head>
	<meta charset="UTF-8">
	<link rel="stylesheet" type="text/css" href="css/rips.css" />
	<?php

	foreach($stylesheets as $stylesheet)
	{
		echo "\t<link type=\"text/css\" href=\"css/$stylesheet.css\" rel=\"";
		if($stylesheet != $default_stylesheet) echo "alternate ";
		echo "stylesheet\" title=\"$stylesheet\" />\n";
	}
	?>
	<script src="js/script.js"></script>
	<script src="js/exploit.js"></script>
	<script src="js/hotpatch.js"></script>
	<script src="js/netron.js"></script>
	<title>RIPS汉化版--BY:J0o1ey QQ547006660</title><!--欢迎各位大佬，小白和我交流-->
    <style type="text/css">
<!--
.STYLE1 {
	font-family: "宋体";
	color: #000000;
}
.STYLE2 {
	color: #FF0000;
	font-weight: bold;
}
.STYLE3 {color: #FF0000}
-->
    </style>
</head>
<body>

<div class="menu">
	<div style="float:left; width:100%;">
	<table width="100%">
	<tr><td width="75%" nowrap>
		<table class="menutable" width="50%" style="float:left;">
		<tr>
			<td nowrap><span class="STYLE2">源码的绝对路径:</span></td>
			<td colspan="3" nowrap><input type="text" size=80 id="location" value="<?php echo BASEDIR; ?>" title="enter path to PHP file(s)" placeholder="/var/www/">
			</td>
			<td nowrap><input type="checkbox" id="subdirs" value="1" title="check to scan subdirectories" checked/>扫描子目录
			</td>
		</tr>
		<tr>
			<td nowrap><span class="STYLE3">扫描级别:</span></td>
			<td nowrap>
				<select id="verbosity" style="width:100%" title="选择扫描级别">
					<?php 
					
						$verbosities = array(
							1 => '1. 只扫描用户选择的',
							2 => '2. 文件/数据库 +1',
							3 => '3. 显示安全 +1,2',
							4 => '4. 未选择的 +1,2,3',
							5 => '5. debug 模式'
						);
						
						foreach($verbosities as $level=>$description)
						{
							echo "<option value=\"$level\">$description</option>\n";							
						}
					?>
				</select>
			</td>
			<td align="right" nowrap><span class="STYLE3">漏洞类型:</span> </td>
			<td>
				<select id="vector" style="width:100%" title="select vulnerability type to scan">
					<?php 
					
						$vectors = array(
							'all' 			=> '全部',
							'server' 		=> '全部服务',							
							'code' 			=> '- 源码泄露',
							'exec' 			=> '- 命令执行',
							'file_read' 	=> '- 文件读取',
							'file_include' 	=> '- 文件包含',							
							'file_affect' 	=> '- 文件操作',
							'ldap' 			=> '- 目录注入',
							'unserialize' 	=> '- PHP对象注入',
							'connect'		=> '- 协议注入',							
							'ri'		 	=> '- 反射注入',
							'database' 		=> '- SQL注入',
							'xpath' 		=> '- XPath注入',
							'other' 		=> '- other',
							'client' 		=> '- 所有的客户端',
							'xss' 			=> '- XSS',
							'httpheader'	=> '- HTTP header注入',
							'fixation'		=> '- 会话固定',
							//'crypto'		=> 'Crypto hints'
						);
						
						foreach($vectors as $vector=>$description)
						{
							echo "<option value=\"$vector\" ";
							if($vector == $default_vector) echo 'selected';
							echo ">$description</option>\n";
						}
					?>
				</select>
			</td>
			<td><input type="button" value="扫描" style="width:100%" class="Button" onClick="scan(false);" title="start scan" /></td>
		</tr>
		<tr>
			<td nowrap>代码样式:</td>
			<td nowrap>
				<select name="stylesheet" id="css" onChange="setActiveStyleSheet(this.value);" style="width:49%" title="select color schema for scan result">
					<?php 
						foreach($stylesheets as $stylesheet)
						{
							echo "<option value=\"$stylesheet\" ";
							if($stylesheet == $default_stylesheet) echo 'selected';
							echo ">$stylesheet</option>\n";
						}
					?>	
				</select>
				<select id="treestyle" style="width:49%" title="select direction of code flow in scan result">
					<option value="1">bottom-up</option>
					<option value="2">top-down</option>
				</select>	
			</td>	
			<td align="right">正则表达式:			</td>
			<td>
				<input type="text" id="search" style="width:100%" />
			</td>
			<td>
				<input type="button" class="Button" style="width:100%" value="查找" onClick="search()" title="search code by regular expression" />
			</td>
		</tr>
		</table>
		<div id="options" style="margin-top:-10px; display:none; text-align:center;" >
			<p class="textcolor">其它选项</p>
			<input type="button" class="Button" style="width:50px" value="文件" onClick="openWindow(5);eval(document.getElementById('filegraph_code').innerHTML);" title="列出扫描的文件" />
			<input type="button" class="Button" style="width:80px" value="用户输入" onClick="openWindow(4)" title="show list of user input" /><br />
			<input type="button" class="Button" style="width:50px" value="状态" onClick="document.getElementById('stats').style.display='block';" title="show scan statistics" />
			<input type="button" class="Button" style="width:80px" value="函数应用" onClick="openWindow(3);eval(document.getElementById('functiongraph_code').innerHTML);" title="show list of user-defined functions" />
		</div>
	</td>
	<td width="25%" align="center" valign="center" nowrap>
		<!-- Logo by Gareth Heyes -->
		<div class="logo"><a id="logo" href="http://shell.mayidui.net" target="_blank" title="汉化者"><?php echo VERSION ?></a></div>
	</td></tr>
	</table>
	</div>
	
	<div style="clear:left;"></div>
</div>
<div class="menushade"></div>

<div class="scanning" id="scanning">客官，淫家正在扫描 ...
<div class="scanned" id="scanned"></div>
</div>

<div id="result">
	
	<div style="margin-left:30px;color:#000000;font-size:14px">
		<h3>快速使用方法:</h3>
	  <p>查找本地PHP源代码路径/文件<b></b> (eg. <em>F:/www/project1/</em> or <em>F:/www/index.php</em>), 选择你需要审计的漏洞类型，并点击扫描!<br>
	    勾选扫描子目录，会将所有子目录包含到扫描中。建议只扫描项目的根目录。子目录中的文件将被PHP代码所包含的RIP自动扫描。然而，启用子目录可以提高扫描结果的成功率（结果显示）。</p>
		<h3>高级骚操作:</h3>
		<p>通过选择不同的扫描级别（默认级别1），调试错误或提高扫描结果。<br>
	    扫描完成后，4个新按钮将出现在右上角。您可以通过在窗口中单击其名称来找到不同类型的漏洞之间的选择。您可以点击右上角的用户输入来获取列表的入口点、列表的函数和所有用户定义的函数或文件的列表，以及所有扫描文件及其包含的图表。所有列表都引用到代码查看器。</p>
		<h3>风格:</h3>
		<p>通过选择不同的代码样式来更改语法高亮模式。<br>
	    在扫描之前，您可以选择代码流应该显示的方式：自下而上或自上而下。.</p>
		<h3>图标:</h3>
		<ul>
		<li class="userinput"><span class="STYLE1"> 用户输入已在这一行中找到。漏洞开发的潜在切入点</span>。<br>
		</li>
		<li class="functioninput"><font color="black">漏洞利用取决于传递给在此行中声明的函数的参数。看看扫描结果中的调用。</font></li>
		<li class="validated"><font color="black">在这一行中检测到用户实现的安全防护。这可能会阻止漏洞检测。</font></li>
		</ul>
		<h3>选项:</h3>
		<ul>
		<li><div class="fileico"></div> 
		      &nbsp;单击文件图标打开代码查看器可以查看原始代码，所有相关的信息高亮显示。<br>
		  通过单击鼠标或通过点击变量来突出变量。通过单击该调用跳入用户定义函数的代码。单击代码查看器底部的“返回”以跳回。这也适用于嵌套函数调用。</li>
		<li><div class="minusico"></div>     &nbsp;单击最小化图标隐藏特定的代码跟踪。您可以稍后再次单击图标显示。</li>
		<li><div class="exploit"></div>   
		    &nbsp;单击目标图标打开导致漏洞的文件。一个新窗口将打开，您可以进入开发细节并创建PHP CURL漏洞代码。</li>
		<li><div class="help"></div>            
		   单击帮助图标以获得该漏洞类型的描述、示例代码、示例开发、修补程序方法和相关的安全功能。</li>
		<li><div class="dataleak"></div>     
		  &nbsp;单击“数据泄漏”图标检查漏洞的输出是否泄漏到某个地方（通过echo/print嵌入到HTTP响应）。</li>
		</ul>
		<h3>提示:</h3>
		<ul><li>RIPS实现静态源代码分析。它只扫描源代码文件，不会执行代码。</li>
		  <li>在此版本中不支持面向对象代码（类）。</li>
		  <li>不要让RIPS的网络接口开放到公共互联网上。只在本地网络服务器上使用。</li>
		  <li class="STYLE2">汉化:J0o1ey' QQ:547006660,Website:http://shell.mayidui.net,欢迎各位大佬、小白、WEB安全培训需求者联系我<a target="_blank" href="http://wpa.qq.com/msgrd?v=3&uin=547006660&site=qq&menu=yes"><img border="0" src="http://wpa.qq.com/pa?p=2:547006660:51" alt="点击这里给我发消息" title="点击这里给我发消息"/></a></li>
		</ul>
	</div>
	
</div>

</body>
</html>