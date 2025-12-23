import { useState, useEffect, useCallback } from 'react';

const STORAGE_KEY = 'vapt-checklist-state';

interface ChecklistState {
  [key: string]: boolean;
}

export const useChecklistStorage = () => {
  const [checkedItems, setCheckedItems] = useState<ChecklistState>({});
  const [isLoaded, setIsLoaded] = useState(false);

  // Load from localStorage on mount
  useEffect(() => {
    try {
      const stored = localStorage.getItem(STORAGE_KEY);
      if (stored) {
        setCheckedItems(JSON.parse(stored));
      }
    } catch (error) {
      console.error('Error loading checklist state:', error);
    }
    setIsLoaded(true);
  }, []);

  // Save to localStorage whenever state changes
  useEffect(() => {
    if (isLoaded) {
      try {
        localStorage.setItem(STORAGE_KEY, JSON.stringify(checkedItems));
      } catch (error) {
        console.error('Error saving checklist state:', error);
      }
    }
  }, [checkedItems, isLoaded]);

  const toggleItem = useCallback((itemId: string) => {
    setCheckedItems(prev => ({
      ...prev,
      [itemId]: !prev[itemId]
    }));
  }, []);

  const isChecked = useCallback((itemId: string): boolean => {
    return checkedItems[itemId] || false;
  }, [checkedItems]);

  const getProgress = useCallback((itemIds: string[]): number => {
    if (itemIds.length === 0) return 0;
    const checked = itemIds.filter(id => checkedItems[id]).length;
    return Math.round((checked / itemIds.length) * 100);
  }, [checkedItems]);

  const resetAll = useCallback(() => {
    setCheckedItems({});
    localStorage.removeItem(STORAGE_KEY);
  }, []);

  const resetSection = useCallback((itemIds: string[]) => {
    setCheckedItems(prev => {
      const next = { ...prev };
      itemIds.forEach(id => {
        delete next[id];
      });
      return next;
    });
  }, []);

  return {
    isChecked,
    toggleItem,
    getProgress,
    resetAll,
    resetSection,
    isLoaded
  };
};
