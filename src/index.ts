import { NativeModulesProxy, EventEmitter, Subscription } from 'expo-modules-core';

// Import the native module. On web, it will be resolved to ExpoKryptom.web.ts
// and on native platforms to ExpoKryptom.ts
import ExpoKryptomModule from './ExpoKryptomModule';
import ExpoKryptomView from './ExpoKryptomView';
import { ChangeEventPayload, ExpoKryptomViewProps } from './ExpoKryptom.types';

// Get the native constant value.
export const PI = ExpoKryptomModule.PI;

export function hello(): string {
  return ExpoKryptomModule.hello();
}

export async function setValueAsync(value: string) {
  return await ExpoKryptomModule.setValueAsync(value);
}

const emitter = new EventEmitter(ExpoKryptomModule ?? NativeModulesProxy.ExpoKryptom);

export function addChangeListener(listener: (event: ChangeEventPayload) => void): Subscription {
  return emitter.addListener<ChangeEventPayload>('onChange', listener);
}

export { ExpoKryptomView, ExpoKryptomViewProps, ChangeEventPayload };
