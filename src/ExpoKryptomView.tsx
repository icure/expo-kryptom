import { requireNativeViewManager } from 'expo-modules-core';
import * as React from 'react';

import { ExpoKryptomViewProps } from './ExpoKryptom.types';

const NativeView: React.ComponentType<ExpoKryptomViewProps> =
  requireNativeViewManager('ExpoKryptom');

export default function ExpoKryptomView(props: ExpoKryptomViewProps) {
  return <NativeView {...props} />;
}
