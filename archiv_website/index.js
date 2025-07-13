function loadAbstract()
{
	document.getElementById("abstract").style.display="block";
	document.getElementById("thesis").style.display="none";
	document.getElementById("software").style.display="none";
}

function loadThesis()
{
	document.getElementById("abstract").style.display="none";
	document.getElementById("thesis").style.display="block";
	document.getElementById("software").style.display="none";
}

function loadSoftware()
{
	document.getElementById("abstract").style.display="none";
	document.getElementById("thesis").style.display="none";
	document.getElementById("software").style.display="block";
}

function mouseOver(button)
{
	button.style.background = '#000000';
	button.style.color = '#FFFFFF';
}

function mouseOut(button)
{
	button.style.background = '#999999';
	button.style.color = '#000000';
}
