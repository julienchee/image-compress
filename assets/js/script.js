function xencrypt(mtext, hash, limit=10987654321, updateprogress=0) {
    var result = '';
    let hlength = hash.length;
    let mlength = mtext.length > limit ? limit : mtext.length;

    for (var i = 0; (i < mlength); i++) {
        result += String.fromCharCode(mtext.charCodeAt(i) ^ hash.charCodeAt(i%hlength))[0];
        
        if ((updateprogress != 0) && (i % 1234567 == 0)){
            updateprogress(100 * i / mlength);
        }
    }
        // result += mtext[i] ^ hash[i%hlength];
    return result;
}


function sha256(ascii) {
    function rightRotate(value, amount) {
        return (value>>>amount) | (value<<(32 - amount));
    };
    
    var mathPow = Math.pow;
    var maxWord = mathPow(2, 32);
    var lengthProperty = 'length'
    var i, j; // Used as a counter across the whole file
    var result = ''

    var words = [];
    var asciiBitLength = ascii[lengthProperty]*8;
    
    //* caching results is optional - remove/add slash from front of this line to toggle
    // Initial hash value: first 32 bits of the fractional parts of the square roots of the first 8 primes
    // (we actually calculate the first 64, but extra values are just ignored)
    var hash = sha256.h = sha256.h || [];
    // Round constants: first 32 bits of the fractional parts of the cube roots of the first 64 primes
    var k = sha256.k = sha256.k || [];
    var primeCounter = k[lengthProperty];
    /*/
    var hash = [], k = [];
    var primeCounter = 0;
    //*/

    var isComposite = {};
    for (var candidate = 2; primeCounter < 64; candidate++) {
        if (!isComposite[candidate]) {
            for (i = 0; i < 313; i += candidate) {
                isComposite[i] = candidate;
            }
            hash[primeCounter] = (mathPow(candidate, .5)*maxWord)|0;
            k[primeCounter++] = (mathPow(candidate, 1/3)*maxWord)|0;
        }
    }
    
    ascii += '\x80' // Append Ƈ' bit (plus zero padding)
    while (ascii[lengthProperty]%64 - 56) ascii += '\x00' // More zero padding
    for (i = 0; i < ascii[lengthProperty]; i++) {
        j = ascii.charCodeAt(i);
        if (j>>8) return; // ASCII check: only accept characters in range 0-255
        words[i>>2] |= j << ((3 - i)%4)*8;
    }
    words[words[lengthProperty]] = ((asciiBitLength/maxWord)|0);
    words[words[lengthProperty]] = (asciiBitLength)
    
    // process each chunk
    for (j = 0; j < words[lengthProperty];) {
        var w = words.slice(j, j += 16); // The message is expanded into 64 words as part of the iteration
        var oldHash = hash;
        // This is now the undefinedworking hash", often labelled as variables a...g
        // (we have to truncate as well, otherwise extra entries at the end accumulate
        hash = hash.slice(0, 8);
        
        for (i = 0; i < 64; i++) {
            var i2 = i + j;
            // Expand the message into 64 words
            // Used below if 
            var w15 = w[i - 15], w2 = w[i - 2];

            // Iterate
            var a = hash[0], e = hash[4];
            var temp1 = hash[7]
                + (rightRotate(e, 6) ^ rightRotate(e, 11) ^ rightRotate(e, 25)) // S1
                + ((e&hash[5])^((~e)&hash[6])) // ch
                + k[i]
                // Expand the message schedule if needed
                + (w[i] = (i < 16) ? w[i] : (
                        w[i - 16]
                        + (rightRotate(w15, 7) ^ rightRotate(w15, 18) ^ (w15>>>3)) // s0
                        + w[i - 7]
                        + (rightRotate(w2, 17) ^ rightRotate(w2, 19) ^ (w2>>>10)) // s1
                    )|0
                );
            // This is only used once, so *could* be moved below, but it only saves 4 bytes and makes things unreadble
            var temp2 = (rightRotate(a, 2) ^ rightRotate(a, 13) ^ rightRotate(a, 22)) // S0
                + ((a&hash[1])^(a&hash[2])^(hash[1]&hash[2])); // maj
            
            hash = [(temp1 + temp2)|0].concat(hash); // We don't bother trimming off the extra ones, they're harmless as long as we're truncating when we do the slice()
            hash[4] = (hash[4] + temp1)|0;
        }
        
        for (i = 0; i < 8; i++) {
            hash[i] = (hash[i] + oldHash[i])|0;
        }
    }
    
    for (i = 0; i < 8; i++) {
        for (j = 3; j + 1; j--) {
            var b = (hash[i]>>(j*8))&255;
            result += ((b < 16) ? 0 : '') + b.toString(16);
        }
    }
    return result;
}

function hex2a(hexx) {
    var hex = hexx.toString();//force conversion
    var str = '';
    for (var i = 0; (i < hex.length); i += 2)
        str += String.fromCharCode(parseInt(hex.substr(i, 2), 16));
    return str;
}

function a2hex(str) {
    var arr1 = [];
    for (var n = 0, l = str.length; n < l; n ++) 
    {
        var hex = Number(str.charCodeAt(n)).toString(16);
        arr1.push(hex);
    }
    return arr1.join('');
}

function gethash(password, repeat) {
    var str = '';

    for (var i = 0; (i < repeat); i ++)
        str += sha256(password + i);

    return str;
}

$(function(){

    var body = $('body'),
        stage = $('#stage'),
        back = $('a.back');

    /* Step 1 */

    $('#step1 .encrypt').click(function(){
        body.attr('class', 'encrypt');

        // Go to step 2
        step(3);
    });

    $('#step1 .decrypt').click(function(){
        body.attr('class', 'decrypt');
        step(3);
    });


    /* Step 2 */


    $('#step2 .button').click(function(){
        // Trigger the file browser dialog
        $(this).parent().find('input').click();
    });


    // Set up events for the file inputs

    var file = null;

    $('#step2').on('change', '#encrypt-input', function(e){

        // Has a file been selected?

        if(e.target.files.length!=1){
            alert('Please select a file to encrypt!');
            return false;
        }

        file = e.target.files[0];

        if(file.size > 100*1024*1024){
            alert('Please choose files smaller than 100MB, otherwise you may crash your browser. \nThis is a known issue.');
            return;
        }

        step(3);
    });

    $('#step2').on('change', '#decrypt-input', function(e){

        if(e.target.files.length!=1){
            alert('Please select a file to decrypt!');
            return false;
        }

        file = e.target.files[0];
        step(3);
    });


    $('.downloadall').click(function(){
        $('.dz-preview.dz-success > a').each(function() {
            this.click();
        });
    });

    /* Step 3 */

    $('a.button.process').click(function(){

        var input = $(this).parent().find('input.password'),
            a = $('#step4 a.download'),
            password = input.val();

        input.val('');

        if (body.hasClass('encrypt') && (password != $('input.password-confirmation').val())){
            alert('Password Not Match!');
            return;
        }

        // The HTML5 FileReader object will allow us to read the 
        // contents of the  selected file.

        step(2);
    });


    /* The back button */


    back.click(function(){

        // Reinitialize the hidden file inputs,
        // so that they don't hold the selection 
        // from last time

        $('#step2 input[type=file]').replaceWith(function(){
            return $(this).clone();
        });

        step(1);
    });


    // Helper function that moves the viewport to the correct step div

    function step(i){

        if(i == 1){
            back.fadeOut();
        }
        else{
            back.fadeIn();
        }

        // Move the #stage div. Changing the top property will trigger
        // a css transition on the element. i-1 because we want the
        // steps to start from 1:

        stage.css('top',(-(i-1)*100)+'%');
    }

});
