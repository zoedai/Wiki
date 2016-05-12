var picW = 101;
var picH = 83;
var numRow = 6;
var numCol = 5;
// Enemies our player must avoid
var Enemy = function(x, y, speed) {
    // Variables applied to each of our instances go here,
    // we've provided one for you to get started
    this.x = x;
    this.y = y * picH;
    this.speed = speed;
    // The image/sprite for our enemies, this uses
    // a helper we've provided to easily load images
    this.sprite = 'images/enemy-bug.png';

}

// Update the enemy's position, required method for game
// Parameter: dt, a time delta between ticks
Enemy.prototype.update = function(dt) {
    // You should multiply any movement by the dt parameter
    // which will ensure the game runs at the same speed for
    // all computers.
    this.x += dt * this.speed;
    if (this.x >= (numCol+1) * picW) {
        this.x = 0;
    }
}

// Draw the enemy on the screen, required method for game
Enemy.prototype.render = function() {
    // console.log(this.sprite);
    ctx.drawImage(Resources.get(this.sprite), this.x, this.y);
}

// Now write your own player class
// This class requires an update(), render() and
// a handleInput() method.
var Player = function(charNo) {
    this.reset();
    // this.sprite = 'images/'+ this.char_img[charNo];
    this.sprite = 'images/char-boy.png';
}

// Player.prototype = Object.create(Enemy.prototype);
Player.prototype.char_img = [
    'char-boy.png',
    'char-cat-girl.png',
    'char-horn-girl.png',
    'char-pink-girl.png',
    'char-princess-girl.png'
]
// Player.prototype.constructor = Player;
Player.prototype.handleInput = function(input) {
    if (input === 'left' && this.col > 0) {
        this.col--;
    } else if (input === 'right' && this.col < numCol-1) {
        this.col++;
    } else if (input === 'down' && this.row < numRow-1) {
        this.row++;
    } else if (input === 'up' && this.row > 0) {
        this.row--;
        if (this.row === 0) {
            this.reset();
        }
    }
}


Player.prototype.update = function() {
    if (this.row >= 1 && this.row <= allEnemies.length) {
        var enemyX = allEnemies[this.row-1].x;
        var playerX = this.getX();

        if (enemyX > playerX - 0.6 * picW && enemyX < playerX + 0.6 * picW) {
            this.reset();
        }
    }
    
}
Player.prototype.render = function() {
    ctx.drawImage(Resources.get(this.sprite), this.getX(), this.getY());
}

Player.prototype.reset = function() {
    this.col = Math.floor(numCol / 2);
    this.row = numRow - 1;
}

Player.prototype.getX = function() {
    return this.col * picW;
}

Player.prototype.getY = function() {
    return this.row * picH; 
}
// Now instantiate your objects.
// Place all enemy objects in an array called allEnemies
// Place the player object in a variable called player

var allEnemies = [];
for (var i = 1; i <= 3; i++) {
    allEnemies.push(new Enemy(0, i, i*50));
}

var player = new Player(2);

// This listens for key presses and sends the keys to your
// Player.handleInput() method. You don't need to modify this.
document.addEventListener('keyup', function(e) {
    var allowedKeys = {
        37: 'left',
        38: 'up',
        39: 'right',
        40: 'down'
    };

    player.handleInput(allowedKeys[e.keyCode]);
});
