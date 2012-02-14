/*
*            DO WHAT THE FUCK YOU WANT TO PUBLIC LICENSE
*                    Version 2, December 2004
*
* Copyright (C) 2004 Sam Hocevar <sam@hocevar.net>
*
* Everyone is permitted to copy and distribute verbatim or modified
* copies of this license document, and changing it is allowed as long
* as the name is changed.
*
*            DO WHAT THE FUCK YOU WANT TO PUBLIC LICENSE
*   TERMS AND CONDITIONS FOR COPYING, DISTRIBUTION AND MODIFICATION
*
*  0. You just DO WHAT THE FUCK YOU WANT TO.
*/

#include "includes.h"

int strccnt(char* str, char c)
{	
	int result = 0;
	while(*str)
	{
		if(*str == c)
		{
			result++;
		}
		str++;
	}
	return result;
}

int arraycnt(void** array)
{
	int result = 0;
	while(*array)
	{
		result++;
		array++;
	}
	return result;
}

/*free_aray renvoie toujours null.
* Ca permet de null la variable que l'on free en un appel
* Pas forcément élégant pour tout le monde,
* mais moi j'aime bien.
*/
char** free_array(char** array)
{
	int objectCount = arraycnt((void**)array);
	int i;
	for(i = 0; i < objectCount; i++)
	{
		free(array[i]);
	}
	free(array);
	return NULL;
}
