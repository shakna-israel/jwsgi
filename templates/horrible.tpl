My name is {foo:(name, last)}

<ul>
{foreach:books:<li>"{{item[1]}}" by {{item[0]}}</li>}
</ul>

{if:rockit:
<p>ROCK IT!</p>
	:
<p>Don't rock it.</p>
}
