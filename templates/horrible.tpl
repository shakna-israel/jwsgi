My name is {foo:(name, last)}

<ul>
{foreach: books:
	<li>"{{item[1]}}" by {{item[0]}}</li>
}
</ul>

<ul>
{foridx: books:
	<li>"{{item[1]}}" by {{item[0]}} (Num: {{idx}})</li>
}
</ul>

{if: rockit:
<p>ROCK IT!</p>
	:
<p>Don't rock it.</p>
}

<p>My filename is {_FILE_}</p>

{include:("include.tpl")}
