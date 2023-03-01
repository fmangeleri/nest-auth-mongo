import { Document } from 'mongoose';
import { Schema, Prop, SchemaFactory } from '@nestjs/mongoose';

@Schema()
export class Feature extends Document {
  @Prop({ required: true, unique: true })
  capacity: number[];

  @Prop()
  color: string[];
}

export const FeatureSchema = SchemaFactory.createForClass(Feature);
