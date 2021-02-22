My name is {foo:(name, last)}

<ul>
{books:foreach:<li>"{{item[1]}}" by {{item[0]}}</li>}
</ul>

{rockit:if:
<p>ROCK IT!</p>
	:
<p>Don't rock it.</p>
}
