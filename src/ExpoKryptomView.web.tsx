import * as React from 'react';

import { ExpoKryptomViewProps } from './ExpoKryptom.types';

export default function ExpoKryptomView(props: ExpoKryptomViewProps) {
  return (
    <div>
      <span>{props.name}</span>
    </div>
  );
}
