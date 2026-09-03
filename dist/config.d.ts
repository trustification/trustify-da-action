export interface ActionConfig {
    mode: string;
    backendUrl?: string;
    providers?: string[];
    sources?: string[];
    groupBy?: string;
    dryRun: boolean;
    labels?: string[];
    branchPrefix?: string;
    sbomTargets?: string[];
    configPath: string;
}
/**
 * Loads configuration from .trustify-da.yml and merges with action inputs.
 * Action inputs override config file values.
 */
export declare function loadConfig(): Promise<ActionConfig>;
