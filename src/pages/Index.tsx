import { useMemo } from 'react';
import { Header } from '@/components/Header';
import { PhaseSection } from '@/components/PhaseSection';
import { SubSection } from '@/components/SubSection';
import { ChecklistItem } from '@/components/ChecklistItem';
import { CodeBlock } from '@/components/CodeBlock';
import { useChecklistStorage } from '@/hooks/useChecklistStorage';
import { checklistData, getPhaseTaskIds, getSubSectionTaskIds, getAllTaskIds } from '@/data/checklistData';
import { ExternalLink } from 'lucide-react';

const Index = () => {
  const { isChecked, toggleItem, getProgress, resetAll, resetSection, isLoaded } = useChecklistStorage();

  const allTaskIds = useMemo(() => getAllTaskIds(), []);
  const totalProgress = useMemo(() => getProgress(allTaskIds), [getProgress, allTaskIds]);

  if (!isLoaded) {
    return (
      <div className="min-h-screen bg-background flex items-center justify-center">
        <div className="text-center">
          <div className="w-8 h-8 border-2 border-primary border-t-transparent rounded-full animate-spin mx-auto mb-4" />
          <p className="text-muted-foreground font-mono text-sm">Loading checklist...</p>
        </div>
      </div>
    );
  }

  return (
    <div className="min-h-screen bg-background">
      <Header totalProgress={totalProgress} onReset={resetAll} />
      
      <main className="container mx-auto px-4 py-8">
        <div className="max-w-4xl mx-auto space-y-6">
          {checklistData.map((phase, phaseIndex) => {
            const phaseTaskIds = getPhaseTaskIds(phase);
            const phaseProgress = getProgress(phaseTaskIds);

            return (
              <PhaseSection
                key={phase.id}
                title={phase.title}
                description={phase.description}
                estimatedTime={phase.estimatedTime}
                progress={phaseProgress}
                phaseNumber={phaseIndex + 1}
                onReset={() => resetSection(phaseTaskIds)}
                defaultOpen={phaseIndex === 0}
              >
                <div className="space-y-4">
                  {phase.subSections.map(subSection => {
                    const subSectionTaskIds = getSubSectionTaskIds(subSection);
                    
                    return (
                      <SubSection
                        key={subSection.id}
                        title={subSection.title}
                        estimatedTime={subSection.estimatedTime}
                        defaultOpen={false}
                      >
                        {/* Tasks */}
                        <div className="space-y-1">
                          {subSection.tasks.map(task => (
                            <ChecklistItem
                              key={task.id}
                              id={task.id}
                              label={task.label}
                              checked={isChecked(task.id)}
                              onToggle={toggleItem}
                            />
                          ))}
                        </div>

                        {/* Manual Checks */}
                        {subSection.manualChecks && subSection.manualChecks.length > 0 && (
                          <div className="mt-4 p-4 rounded-lg bg-info/5 border border-info/20">
                            <h4 className="text-sm font-medium text-info mb-3 flex items-center gap-2">
                              <ExternalLink className="h-4 w-4" />
                              Manual Sources
                            </h4>
                            <ul className="space-y-2">
                              {subSection.manualChecks.map((check, idx) => (
                                <li key={idx} className="text-xs text-muted-foreground font-mono">
                                  {check}
                                </li>
                              ))}
                            </ul>
                          </div>
                        )}

                        {/* Code Snippets */}
                        {subSection.codeSnippets && subSection.codeSnippets.length > 0 && (
                          <div className="mt-4 space-y-3">
                            {subSection.codeSnippets.map((snippet, idx) => (
                              <CodeBlock
                                key={idx}
                                title={snippet.title}
                                code={snippet.code}
                              />
                            ))}
                          </div>
                        )}
                      </SubSection>
                    );
                  })}
                </div>
              </PhaseSection>
            );
          })}
        </div>

        {/* Footer */}
        <footer className="max-w-4xl mx-auto mt-12 pt-8 border-t border-border/50">
          <div className="text-center">
            <p className="text-xs text-muted-foreground font-mono">
              VAPT Checklist • Progress saved automatically
            </p>
          </div>
        </footer>
      </main>
    </div>
  );
};

export default Index;
