// Maps displayed criticality and severity values to the shared semantic color classes.
export function semanticLevelClass(value: string | null | undefined): string {
  switch ((value || '').trim().toLocaleLowerCase()) {
    case 'critical':
      return 'semantic-level-critical';
    case 'high':
      return 'semantic-level-high';
    case 'medium':
      return 'semantic-level-medium';
    case 'low':
      return 'semantic-level-low';
    default:
      return '';
  }
}
