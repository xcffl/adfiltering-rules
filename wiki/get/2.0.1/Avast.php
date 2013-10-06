<?php

function downfile($fileurl)
{
$filename=$fileurl;
$file   =   fopen($filename, "rb");
Header( "Content-type:   application/ini ");
Header( "Accept-Ranges:   bytes ");
Header( "Content-Disposition:   attachment;   filename= WebShield.ini");


$contents = "";
while (!feof($file)) {
  $contents .= fread($file, 8192);
}
echo $contents;
fclose($file);

}
$url="http://adfiltering-rules.googlecode.com/svn/trunk/lastest/WebShield.ini";
downfile($url);

?>