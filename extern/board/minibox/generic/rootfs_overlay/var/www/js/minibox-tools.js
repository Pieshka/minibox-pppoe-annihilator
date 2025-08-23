// @license magnet:?xt=urn:btih:d3d9a9a6595521f9666a5e94cc830dab83b65699&dn=expat.txt Expat

//////////////////////////
//                      //
// Minibox Tools Script //
//                      //
//////////////////////////

/* Useful utilities and functions, that doesn't fit into the main script */


/* These Alpine.js mask functions are the smartest and dumbest thing
   I've ever created.
*/
window.mnbox_getMacMask = function (input) 
{
    const value = input.toUpperCase().replaceAll(':', '');
    let mask = '';
    let validLength = 0;

    for (let i = 0; i < value.length && validLength < 12; i++) 
    {
        const char = value[i];

        if (/^[0-9A-F]$/.test(char)) 
        {
            if (/^[0-9]$/.test(char)) mask += '9';
            else mask += 'a';
            validLength++;
        } 
        else if (/^[A-Z]$/.test(char)) 
        {
            mask += '9';
            validLength++;
        } 
        else 
        {
            mask += 'a';
            validLength++;
        }

        if (validLength % 2 === 0 && validLength < 12) 
        {
            mask += ':';
        }
    }

    return mask;
};

window.mnbox_getIpMask = function (input) 
{
    const value = input;
    let mask = '';
    let digitCount = 0;
    let dotCount = 0;
    let currentOctet = '';

    for (let i = 0; i < value.length; i++) 
    {
        if (dotCount >= 3 && digitCount >= 3) break;

        const char = value[i];
        if (char === '.') 
        {
            if (digitCount > 0 && dotCount < 3) {
                mask += '.';
                digitCount = 0;
                dotCount++;
                currentOctet = '';
            }
        } 
        else 
        {

            currentOctet += char;
            digitCount++;

            const octetValue = parseInt(currentOctet, 10);
            const hasLetter = /[A-Za-z]/.test(currentOctet);
            const isInvalid = octetValue > 255;

            if (hasLetter) 
            {
                mask += '9';
            } 
            else 
            {
                mask += isInvalid ? 'a' : '9';
            }

            if (digitCount === 3 && dotCount < 3)
            {
                mask += '.';
                digitCount = 0;
                dotCount++;
                currentOctet = '';
            }
        }
    }
    return mask;
};

// @license-end