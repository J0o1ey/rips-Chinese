<?php
/** 

RIPS - A static source code analyser for vulnerabilities in PHP scripts 
	by Johannes Dahse (johannes.dahse@rub.de)
			
			
Copyright (C) 2012 Johannes Dahse

This program is free software; you can redistribute it and/or modify it under the terms of the GNU General Public License as published by the Free Software Foundation; either version 3 of the License, or (at your option) any later version.

This program is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for more details.

You should have received a copy of the GNU General Public License along with this program; if not, see <http://www.gnu.org/licenses/>.	

**/

final class Info
{	
	// interesting functions, output and comment them if seen
	public static $F_INTEREST = array(
		'phpinfo'						=> '检测到存在phpinfo文件',
		'registerPHPFunctions'			=> 'registerPHPFunctions()允许在XML代码执行',
		'session_start'					=> '使用 sessions',
		#'session_destroy'				=> 'session_destroy(), delete arbitrary file in PHP 5.1.2',
		'dbase_open' 					=> '使用 DBMS dBase',
		'dbplus_open' 					=> '使用 DBMS DB++',
		'dbplus_ropen' 					=> '使用 DBMS DB++',
		'fbsql_connect' 				=> '使用 DBMS FrontBase' ,
		'ifx_connect'					=> '使用 DBMS Informix',
		'db2_connect'					=> '使用 DBMS IBM DB2',
		'db2_pconnect'					=> '使用 DBMS IBM DB2',
		'ftp_connect'					=> '使用 FTP server', 
		'ftp_ssl_connect' 				=> '使用 FTP server', 
		'ingres_connect'				=> '使用 DBMS Ingres',
		'ingres_pconnect'				=> '使用 DBMS Ingres',
		'ldap_connect'					=> '使用 LDAP server',
		'msession_connect'	 			=> '使用 msession server',
		'msql_connect'					=> '使用 DBMS mSQL',
		'msql_pconnect'					=> '使用 DBMS mSQL',
		'mssql_connect'					=> '使用 DBMS MS SQL',
		'mssql_pconnect'				=> '使用 DBMS MS SQL',
		'mysql_connect'					=> '使用 DBMS MySQL',
		#'mysql_escape_string'			=> 'insecure mysql_escape_string',
		'mysql_pconnect'				=> '使用 DBMS MySQL',
		'mysqli'						=> '使用 DBMS MySQL, MySQLi Extension',
		'mysqli_connect'				=> '使用 DBMS MySQL, MySQLi Extension',
		'mysqli_real_connect'			=> '使用 DBMS MySQL, MySQLi Extension',
		'oci_connect'					=> '使用 DBMS Oracle OCI8',
		'oci_new_connect'				=> '使用 DBMS Oracle OCI8',
		'oci_pconnect'					=> '使用 DBMS Oracle OCI8',
		'ocilogon'						=> '使用 DBMS Oracle OCI8',
		'ocinlogon'						=> '使用 DBMS Oracle OCI8',
		'ociplogon'						=> '使用 DBMS Oracle OCI8',
		'ora_connect'					=> '使用 DBMS Oracle',
		'ora_pconnect'					=> '使用 DBMS Oracle',
		'ovrimos_connect'				=> '使用 DBMS Ovrimos SQL',
		'pg_connect'					=> '使用 DBMS PostgreSQL',
		'pg_pconnect'					=> '使用 DBMS PostgreSQL',
		'sqlite_open'					=> '使用 DBMS SQLite',
		'sqlite_popen'					=> '使用 DBMS SQLite',
		'SQLite3'						=> '使用 DBMS SQLite3',
		'sybase_connect'				=> '使用 DBMS Sybase',
		'sybase_pconnect'				=> '使用 DBMS Sybase',
		'TokyoTyrant'					=> '使用 DBMS TokyoTyrant',
		'xptr_new_context'				=> '使用 XML document',
		'xpath_new_context'				=> '使用 XML document'
	);	
	
	// interesting functions for POP/Unserialze
	public static $F_INTEREST_POP = array(
		'__autoload'					=> 'function __autoload',
		'__destruct'					=> 'POP gagdet __destruct',
		'__wakeup'						=> 'POP gagdet __wakeup',
		'__toString'					=> 'POP gagdet __toString',
		'__call'						=> 'POP gagdet __call',
		'__callStatic'					=> 'POP gagdet __callStatic',
		'__get'							=> 'POP gagdet __get',
		'__set'							=> 'POP gagdet __set',
		'__isset'						=> 'POP gagdet __isset',
		'__unset'						=> 'POP gagdet __unset'
	);
	
}

?>	