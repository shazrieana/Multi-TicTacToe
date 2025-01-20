// tests/tictactoe.test.js
const { checkWinner } = require('../src/tictactoe');

test('X wins horizontally', () => {
  const board = [
    ['X', 'X', 'X'],
    ['O', ' ', 'O'],
    [' ', ' ', ' ']
  ];
  expect(checkWinner(board)).toBe('X');
});

test('O wins vertically', () => {
  const board = [
    ['O', 'X', ' '],
    ['O', 'X', ' '],
    ['O', ' ', 'X']
  ];
  expect(checkWinner(board)).toBe('O');
});

test('Draw game', () => {
  const board = [
    ['X', 'O', 'X'],
    ['X', 'X', 'O'],
    ['O', 'X', 'O']
  ];
  expect(checkWinner(board)).toBe(null);
});