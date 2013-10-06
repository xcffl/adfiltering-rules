<?php

function downfile($fileurl)
{
$filename=$fileurl;
$file   =   fopen($filename, "rb");
Header( "Content-type:   application/css ");
Header( "Accept-Ranges:   bytes ");
Header( "Content-Disposition:   attachment;   filename= urlfilter.css");


$contents = "";
while (!feof($file)) {
  $contents .= fread($file, 8192);
}
echo $contents;
fclose($file);

}
$url="http://adfiltering-rules.googlecode.com/svn/trunk/lastest/urlfilter.css";
downfile($url);

?>