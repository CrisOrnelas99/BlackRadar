import { semanticLevelClass } from './semantic-level';

describe('semanticLevelClass', () => {
  it.each([
    ['Critical', 'semantic-level-critical'],
    ['HIGH', 'semantic-level-high'],
    [' Medium ', 'semantic-level-medium'],
    ['low', 'semantic-level-low'],
  ])('maps %s to %s', (value, expectedClass) => {
    expect(semanticLevelClass(value)).toBe(expectedClass);
  });

  it.each([undefined, null, '', 'Unknown'])('returns no class for %s', (value) => {
    expect(semanticLevelClass(value)).toBe('');
  });
});
